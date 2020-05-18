use libc::{
    c_char, fd_set, localtime, select, size_t, strerror, time, timeval, tm, FD_ISSET, FD_SET,
    FD_ZERO,
};
use std::{
    env,
    ffi::{CStr, CString},
    fs::File,
    io::{self, BufRead, BufReader, Write},
    mem::{size_of_val, MaybeUninit},
    net,
    os::unix::io::{FromRawFd, IntoRawFd},
    ptr,
};

extern "C" {
    fn strftime(s: *mut c_char, max: size_t, format: *const c_char, tm: *const tm) -> usize;
}

const DEFAULT_HOST: &str = "irc.oftc.net";
const DEFAULT_PORT: u16 = 6667;
const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %R";
const COMMAND_PREFIX_CHARACTER: char = ':';
const DEFAULT_PARTING_MESSAGE: &str = "sic - 250 LOC are too much!";

static mut CHANNEL: Option<String> = None;
static mut NICK: Option<String> = None;

fn error<S: AsRef<str>>(msg: S) {
    let msg = msg.as_ref();
    eprint!("{}", msg);
    if msg.ends_with(':') {
        if let Some(code) = io::Error::last_os_error().raw_os_error() {
            eprintln!(
                " {}",
                unsafe { CStr::from_ptr(strerror(code)) }.to_string_lossy()
            );
        }
    }
}

fn dial(host: &str, port: u16) -> net::TcpStream {
    match net::TcpStream::connect((host, port)) {
        Ok(stream) => stream,
        Err(_) => {
            error(format!("Failed to connect to host: '{}'", host));
            std::process::exit(1);
        }
    }
}

fn user() -> Option<String> {
    match env::var("USER") {
        Ok(name) => Some(name),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(invalid)) => Some(invalid.to_string_lossy().to_string()),
    }
}

fn print_message(in_channel: &str, message: &str) {
    let mut buf: [u8; 80] = [0; 80];
    let time_str = unsafe {
        let t = time(ptr::null_mut());
        strftime(
            buf.as_mut_ptr() as _,
            size_of_val(&buf),
            CString::new(TIMESTAMP_FORMAT)
                .expect("Invalid timestamp format")
                .as_ptr(),
            localtime(&t),
        );
        CStr::from_bytes_with_nul_unchecked(&buf)
    };
    println!("{}: {} {}", in_channel, time_str.to_string_lossy(), message);
}

fn private_message(srv: &mut net::TcpStream, chan: Option<&String>, msg: &str) -> io::Result<()> {
    if let Some(chan) = chan {
        print_message(
            chan,
            &format!("<{}> {}", unsafe { NICK.as_ref().unwrap() }, msg),
        );
        write!(srv, "PRIVMSG {} :{}\r\n", chan, msg)?;
    } else {
        eprintln!("No channel to send to");
    }
    Ok(())
}

fn parse_input(srv: &mut net::TcpStream, input: String) -> io::Result<()> {
    let input = input.trim_matches('\n');
    if input.is_empty() {
        return Ok(());
    }

    if !input.starts_with(COMMAND_PREFIX_CHARACTER) {
        private_message(srv, unsafe { CHANNEL.as_ref() }, input)?;
        return Ok(());
    }

    let parts: Vec<_> = input
        .trim_start_matches(COMMAND_PREFIX_CHARACTER)
        .split_whitespace()
        .collect();
    if parts.len() > 0 {
        match parts[0] {
            "j" | "join" => {
                if parts.len() == 2 {
                    write!(srv, "JOIN {}\r\n", parts[1])?;
                    unsafe {
                        if CHANNEL.is_none() {
                            CHANNEL.replace(parts[1].to_string());
                        }
                    }
                } else {
                    eprintln!("Invalid join syntax");
                }
            }
            "l" | "leave" => {
                let channel_to_leave = parts
                    .get(1)
                    .cloned()
                    .or(unsafe { CHANNEL.as_ref() }.map(|s| s.as_str()));
                let parting_message = parts.get(2).cloned().unwrap_or(DEFAULT_PARTING_MESSAGE);
                if let Some(channel_to_leave) = channel_to_leave {
                    write!(srv, "PART {} :{}\r\n", channel_to_leave, parting_message)?;
                } else {
                    eprintln!("Not in a channel");
                }
            }
            "m" | "message" => {
                if parts.len() != 3 {
                    eprintln!("Invalid message syntax");
                } else {
                    let dest = parts[1];
                    let message = parts[2..].join(" ");
                    private_message(srv, Some(&dest.to_string()), &message)?;
                }
            }
            "s" | "set-channel" => {
                if parts.len() != 2 {
                    eprintln!("Invalid set-channel syntax");
                } else {
                    unsafe {
                        CHANNEL.replace(parts[1].to_string());
                    }
                }
            }
            _ => write!(srv, "{}", input)?,
        }
    } else {
        eprintln!("Invalid command syntax");
    }

    Ok(())
}

fn parse_response(srv: &mut net::TcpStream, host: &str, msg: String) -> io::Result<()> {
    if msg.is_empty() {
        return Ok(());
    }

    let mut usr = host;
    let mut cmd = &msg[..];
    if cmd.starts_with(':') {
        if let Some(idx) = msg.find(' ') {
            usr = &cmd[1..idx];
            cmd = &cmd[idx + 1..];
            if let Some(idx) = usr.rfind('!') {
                usr = &usr[..idx];
            }
        } else {
            unreachable!();
        }
    }

    let mut param = if let Some(idx) = cmd.find(' ') {
        let param = &cmd[idx + 1..];
        cmd = &cmd[..idx];
        param
    } else {
        unreachable!();
    };

    let txt = if let Some(idx) = param.find(':') {
        let txt = &param[idx + 1..];
        param = &param[..idx].trim_end();
        txt
    } else {
        ""
    };

    if cmd == "PONG" {
        return Ok(());
    }

    match cmd {
        "PRIVMSG" => print_message(param, &format!("<{}> {}", usr, txt)),
        "PING" => write!(srv, "PONG {}\r\n", txt)?,
        cmd => {
            print_message(usr, &format!(">< {} ({}): {}", cmd, param, txt));
            if cmd == "NICK" {
                unsafe {
                    NICK.replace(txt.to_string());
                }
            }
        }
    }

    Ok(())
}

fn usage() {
    eprintln!(
        "usage: sic-rs [-h|--host host] [-p|--port port] [-n|--nick nick] [-k|--keyword password]"
    );
    std::process::exit(1);
}

fn main() -> io::Result<()> {
    unsafe {
        NICK.replace(user().unwrap_or_else(|| "unknown".to_string()));
    }

    let mut host = DEFAULT_HOST.to_string();
    let mut port = DEFAULT_PORT;
    let mut password = None;

    let mut args = env::args();
    while let Some(arg) = args.next() {
        macro_rules! with_arg {
            (|$argname:ident| $($do:tt)*) => {
                if let Some($argname) = args.next() { $($do)* } else { usage(); }
            }
        }

        if arg.starts_with('-') {
            match &arg[1..] {
                "n" | "-nick" => with_arg! { |arg|
                    unsafe { NICK.replace(arg); }
                },
                "p" | "-port" => with_arg! { |arg|
                    if let Ok(p) = arg.parse() {
                        port = p;
                    } else {
                        error("Invalid port");
                    }
                },
                "h" | "-host" => with_arg! { |arg|
                        host = arg;
                },
                "k" | "-keyword" => with_arg! { |arg|
                    password = Some(arg);
                },

                _ => usage(),
            }
        }
    }

    let mut rd = MaybeUninit::<fd_set>::uninit();
    let tv = MaybeUninit::<timeval>::uninit();
    let mut trespond = 0;

    let mut srv_write = dial(&host, port);
    srv_write.set_nonblocking(true)?;
    let srv_read = srv_write.try_clone()?;
    let nick = unsafe { NICK.as_ref() }.unwrap();
    if let Some(password) = password {
        write!(srv_write, "PASS {}\r\n", password)?;
    }
    write!(srv_write, "NICK {}\r\n", nick)?;
    write!(srv_write, "USER {} localhost {} :{}\r\n", nick, host, nick)?;

    // unbuffered
    let mut stdin = BufReader::new(unsafe { File::from_raw_fd(0) });
    let srv_fd = srv_write.try_clone()?.into_raw_fd();
    let mut srv = unsafe { File::from_raw_fd(srv_fd) };
    let mut srv_read = BufReader::new(srv_read);

    loop {
        let n = unsafe {
            FD_ZERO(rd.as_mut_ptr());
            rd.assume_init();
            FD_SET(0 /* stdin */, rd.as_mut_ptr());
            FD_SET(srv_fd, rd.as_mut_ptr());
            let mut tv = tv.assume_init();
            tv.tv_sec = 120;
            tv.tv_usec = 0;
            select(
                srv_fd + 1,
                rd.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut tv,
            )
        };

        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            error("sic: error on select():");
        } else if n == 0 {
            if unsafe { time(ptr::null_mut()) } - trespond >= 300 {
                error("sic shutting down: parse timeout\n");
                break;
            }
            write!(srv, "PING {}\r\n", host)?;
            continue;
        }

        if unsafe { FD_ISSET(srv_fd, rd.as_mut_ptr()) } {
            for line in (&mut srv_read).lines() {
                parse_response(
                    &mut srv_write,
                    &host,
                    match line {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        whatever_else => whatever_else?,
                    },
                )?;
            }
            trespond = unsafe { time(ptr::null_mut()) };
        }
        if unsafe {
            FD_ISSET(0 /* stdin */, rd.as_mut_ptr())
        } {
            let mut buf = String::new();
            stdin.read_line(&mut buf)?;
            parse_input(&mut srv_write, buf)?;
        }
    }

    Ok(())
}