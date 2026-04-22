#!/bin/bash
# Decrypt sspanel-style AES-128-CBC subscription response (JSON: {"content":"base64(iv+ciphertext)","aesEncrypted":true})
# Usage: source this file, set CFG_FILE and subscribe_decrypt_key (plaintext login password), then call sub_decrypt
# Key is derived as MD5(password), same as v2rayN / sspanel when pwdMethod=md5 and salt=empty
# Returns: 0, overwrites CFG_FILE with decrypted YAML on success

sub_decrypt() {
   [ -z "$subscribe_decrypt_key" ] && return 0
   [ ! -s "$CFG_FILE" ] && return 0
   grep -q '"aesEncrypted"' "$CFG_FILE" 2>/dev/null || return 0
   grep -q '"content"' "$CFG_FILE" 2>/dev/null || return 0

   # User inputs plaintext login password only; key = MD5(password), same as v2rayN
   key_hex=$(echo -n "$subscribe_decrypt_key" | md5sum | awk '{print $1}')
   [ -z "$key_hex" ] || [ ${#key_hex} -ne 32 ] && return 0

   content_b64=$(sed -n 's/.*"content":"\([^"]*\)".*/\1/p' "$CFG_FILE")
   [ -z "$content_b64" ] && return 0

   RAW=$(mktemp)
   IV_BIN=$(mktemp)
   CT_BIN=$(mktemp)
   trap 'rm -f "$RAW" "$IV_BIN" "$CT_BIN"' RETURN

   echo "$content_b64" | base64 -d > "$RAW" 2>/dev/null || return 0
   [ ! -s "$RAW" ] && return 0

   dd if="$RAW" of="$IV_BIN" bs=1 count=16 2>/dev/null
   dd if="$RAW" of="$CT_BIN" bs=1 skip=16 2>/dev/null
   iv_hex=$(od -A n -t x1 -N 16 "$IV_BIN" 2>/dev/null | tr -d ' \n')
   [ -z "$iv_hex" ] || [ ${#iv_hex} -ne 32 ] && return 0

   if openssl enc -d -aes-128-cbc -K "$key_hex" -iv "$iv_hex" -in "$CT_BIN" -out "${CFG_FILE}.dec" 2>/dev/null && [ -s "${CFG_FILE}.dec" ]; then
      mv "${CFG_FILE}.dec" "$CFG_FILE"
      LOG_OUT "Tip: Subscription decrypted (sspanel AES) successfully."
   fi
   return 0
}
