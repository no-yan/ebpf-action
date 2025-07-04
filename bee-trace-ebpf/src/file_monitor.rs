use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use bee_trace_common::SecretAccessEvent;
use core::str;

#[map]
static SECRET_ACCESS_EVENTS: PerfEventArray<SecretAccessEvent> = PerfEventArray::new(0);

#[map]
static WATCHED_PATTERNS: HashMap<[u8; 64], u8> = HashMap::with_max_entries(128, 0);

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_openat(ctx) }.unwrap_or(1)
}

#[inline(never)]
unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    // Get the filename from the tracepoint arguments
    let path_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;

    if path_ptr.is_null() {
        return Ok(0);
    }

    // Read the filename from user space
    let mut path_buf = [0u8; 128];
    let path_len = bpf_probe_read_user_str_bytes(path_ptr, &mut path_buf)
        .map_err(|_| 1i64)?
        .len();

    // ★★★ 修正ポイント 1 ★★★
    // 元のバイトスライスを先に変数として定義しておく
    let path_slice = &path_buf[..path_len];

    // ログ出力のために一度文字列に変換
    let filename_str = str::from_utf8_unchecked(path_slice);
    info!(&ctx, "monitoring file access: {}", filename_str);

    // ★★★ 修正ポイント 2 (ロジックのバグ修正) ★★★
    // is_sensitive_fileには、バッファ全体(`&path_buf`)ではなく、
    // 有効なデータ部分のスライス(`path_slice`)を渡す
    if !is_sensitive_file(path_slice) {
        return Ok(0);
    }

    // 以下9行をコメントアウトするとeBPF verifyに成功する
    // 1. バイトスライスを渡して、ベースネームの開始インデックスを取得
    // let basename_start_idx = get_basename_start_index(path_slice);
    //
    // // 2. 「元のバイトスライス」から、ベースネームのサブスライスを作成
    // // SAFETY: basename_start_idx is computed so that
    // //         0 ≤ basename_start_idx ≤ path_slice.len()
    // let basename_slice = unsafe {
    //     core::slice::from_raw_parts(
    //         path_slice.as_ptr().add(basename_start_idx),
    //         path_slice.len() - basename_start_idx,
    //     )
    // };
    //
    // // 3. ログ出力の直前で、ベースネームのバイトスライスを文字列に変換
    // let basename_str = str::from_utf8_unchecked(basename_slice);
    // info!(&ctx, "basename test: {}", basename_str);

    // (2) 末尾から '/' を探す ── get_unchecked で境界チェックを回避
    let mut i = path_len;
    while i > 0 {
        i -= 1;
        // ★ get_unchecked なので panic パスは生成されない
        if *path_buf.get_unchecked(i) == b'/' {
            i += 1; // '/' の次が basename
            break;
        }
    }
    let basename_len = path_len - i;

    // (3) basename を固定長バッファへコピーし NUL 終端
    let mut basename_c = [0u8; 64];
    let copy_len = core::cmp::min(basename_len, 63);
    core::ptr::copy_nonoverlapping(
        path_buf.as_ptr().add(i), // コピー元
        basename_c.as_mut_ptr(),  // コピー先
        copy_len,
    );
    // basename_c はゼロ初期化済みなので末尾に NUL が入る

    // (4) printk 用に %s + ポインタで出力
    info!(&ctx, "basename=%s\0", basename_c.as_ptr());

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: bee_trace_common::AccessType::File,
        // ★★★ 修正ポイント 4 (型の整合性) ★★★
        // path_lenはusizeなので、structの型(おそらくu32)にキャストする
        path_len: path_len.min(128),
        path_or_var: [0u8; 128],
    };

    // Copy the filename to the event
    let copy_len = path_len.min(event.path_or_var.len());
    event.path_or_var[..copy_len].copy_from_slice(&path_buf[..copy_len]);

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
    Ok(0)
}
// #[inline]
// unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
//     // Get the filename from the tracepoint arguments
//     let path_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;
//
//     if path_ptr.is_null() {
//         return Ok(0);
//     }
//
//     // Read the filename from user space
//     let mut path_buf = [0u8; 128];
//     let path_len = bpf_probe_read_user_str_bytes(path_ptr, &mut path_buf)
//         .map_err(|_| 1i64)?
//         .len();
//
//     // Check if the file matches any watched patterns
//     let path_slice = &path_buf[..path_len];
//     let filename_str = str::from_utf8_unchecked(path_slice);
//     info!(&ctx, "monitoring file access: {}", filename_str);
//
//     if !is_sensitive_file(&path_buf) {
//         return Ok(0);
//     }
//
//     // let basename_str = str::from_utf8_unchecked(&basename!(filename));
//     // info!(&ctx, "basename test: {}", basename_str);
//     // Log when sensitive file is detected
//     let basename_idx = get_basename_start_index(&path_buf[..path_len]);
//     let basename_slice = &path_slice[basename_idx..];
//     let basename_str = str::from_utf8_unchecked(basename_slice);
//     info!(&ctx, "basename test: {}", basename_str);
//
//     let Ok(comm) = ctx.command() else {
//         return Ok(0);
//     };
//
//     let mut event = SecretAccessEvent {
//         pid: ctx.pid(),
//         uid: ctx.uid(),
//         comm,
//         access_type: bee_trace_common::AccessType::File,
//         path_or_var: [0u8; 128],
//         path_len: path_len.min(128),
//     };
//
//     // Copy the filename to the event
//     let copy_len = (path_len as usize).min(event.path_or_var.len());
//     event.path_or_var[..copy_len].copy_from_slice(&path_buf[..copy_len]);
//
//     SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
//     info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
//     Ok(0)
// }

#[inline(never)]
fn is_sensitive_file(filename: &[u8]) -> bool {
    //
    // let basename = &filename[basename_start_idx..filename.len()];
    // let basename_str = str::from_utf8_unchecked(basename);
    // if basename_str.starts_with("credentials.json")
    //     || basename_str.starts_with("id_rsa")
    //     || basename_str.starts_with("id_dsa")
    //     || basename_str.starts_with("id_ecdsa")
    //     || basename_str.starts_with("id_ed25519")
    //     || basename_str.starts_with(".env")
    //     || basename_str.starts_with("config.json")
    //     || basename_str.starts_with("secrets.yaml")
    //     || basename_str.starts_with("secrets.yml")
    //     || basename_str.starts_with("private.key")
    // {
    //     return true;
    // }

    if filename.len() < 4 {
        return false;
    }

    let start = filename.len() - 4;
    let ext = &filename[start..start + 4];
    if ext == b".pem"
        || ext == b".key"
        || ext == b".p12"
        || ext == b".pfx"
        || ext == b".crt"
        || ext == b".cer"
        || ext == b".der"
    {
        return true;
    }

    false
}

#[inline(never)]
fn get_basename_start_index(path: &[u8]) -> usize {
    let len = path.len();
    if len == 0 {
        return 0;
    }

    // 有界ループで末尾から '/' を探す
    for i in 0..128 {
        if i >= len {
            break;
        }

        let current_idx = len - 1 - i;
        if path[current_idx] == b'/' {
            // '/' が見つかったら、その次のインデックスを返す。
            // これだけで、末尾のスラッシュ(例: "/a/b/")のケースも
            // 正しく処理され、空のベースネームの開始位置(len)が返る。
            return current_idx + 1;
        }

        if current_idx == 0 {
            break;
        }
    }

    // '/' が見つからなければ、ベースネームは先頭(インデックス0)から始まる
    0
}
