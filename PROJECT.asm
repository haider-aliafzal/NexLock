; +--------------------------------------------------------------+
; ¦           NexLock — 8086 Based Secure Access System          ¦
; ¦                    For EMU8086 Emulator                      ¦
; +--------------------------------------------------------------+
;
; HOW THIS PROGRAM IS ORGANIZED
; ------------------------------
; The program is split into PROCEDURES (like functions in C++).
; Each procedure does one job. They call each other using CALL
; and return using RET — exactly like function calls in C++.
;
; CALL flow:
;   main
;   +-- SHOW_WELCOME
;   +-- REGISTER_USER
;   +-- LOGIN
;   ¦     +-- LOCK_ACCOUNT
;   +-- MAIN_MENU
;         +-- ENCRYPT_MSG
;         +-- DECRYPT_MSG
;         +-- STORE_NOTE
;         +-- VIEW_NOTE
;         +-- (logout ? returns from MAIN_MENU)
;
; KEY REGISTERS USED THROUGHOUT
; ------------------------------
; AL  — general purpose: holds single characters, return values
; AH  — service number for INT 21h calls
; DX  — address of string to print (for INT 21h / AH=09h)
; SI  — source pointer (read from here)
; DI  — destination pointer (write to here)
; CX  — counter for loops
; BL/BH — temporary storage when AL is about to be overwritten
;
; INT 21h CHEAT SHEET
; -------------------
; AH=09h  ? print a '$'-terminated string. DX = address of string.
; AH=02h  ? print a single character.      DL = the character.
; AH=0Ah  ? read a line of input (stops on Enter). DX = buffer address.
; AH=4Ch  ? exit the program.

; --------------------------------------------------------------
;  ASSEMBLER DIRECTIVES
;  These are not instructions — they tell the assembler how to
;  set up memory. Think of them as configuration lines.
; --------------------------------------------------------------
.model small    ; one 64KB segment for code, one 64KB for data
.stack 100h     ; reserve 256 bytes for the stack

; --------------------------------------------------------------
;  DATA SECTION
;  Everything declared here lives in memory from the start.
;  'db' = Define Byte(s).  13,10 = carriage return + line feed
;  (that's how DOS moves to a new line on screen).
;  '$' marks the end of a printable string for INT 21h/AH=09h.
;  '0' (number zero) marks the end of strings we compare.
; --------------------------------------------------------------
.data

; -- Welcome Screen strings -----------------------------------
msg_welcome     db '+--------------------------+', 13, 10
                db '|       N E X L O C K      |', 13, 10
                db '|   Secure Access System   |', 13, 10
                db '+--------------------------+', 13, 10, '$'
msg_menu_main   db 13, 10, '  1. Login', 13, 10
                db '  2. Register', 13, 10
                db 13, 10, '  Enter choice: $'

; -- Register strings -----------------------------------------
msg_reg_user    db 13, 10, '  Enter new username: $'
msg_reg_pass    db 13, 10, '  Enter new password: $'
msg_reg_ok      db 13, 10, '  [OK] Account created!', 13, 10, '$'

; -- Login strings --------------------------------------------
msg_login_user  db 13, 10, '  Username: $'
msg_login_pass  db 13, 10, '  Password: $'
msg_login_ok    db 13, 10, '  [OK] Login successful!', 13, 10, '$'
msg_login_fail  db 13, 10, '  [!] Wrong credentials. Attempts left: $'
msg_locked      db 13, 10, '  [!!] ACCOUNT LOCKED. Please wait...', 13, 10, '$'
msg_restored    db 13, 10, '  Access restored. Try again.', 13, 10, '$'

; -- Main Menu string -----------------------------------------
msg_main_menu   db 13, 10, '==========================', 13, 10
                db '        MAIN  MENU', 13, 10
                db '==========================', 13, 10
                db '  1. Encrypt a Message', 13, 10
                db '  2. Decrypt a Message', 13, 10
                db '  3. Store a Note', 13, 10
                db '  4. View Stored Note', 13, 10
                db '  5. Logout', 13, 10
                db 13, 10, '  Enter choice: $'

; -- Encrypt / Decrypt strings --------------------------------
; Prompts end with 13,10 so the cursor is on a fresh line
; when the user starts typing — prevents console wrap + backspace issues.
msg_enc_prompt  db 13, 10, '  Enter message to encrypt (max 75 chars):', 13, 10, '  > $'
msg_enc_result  db 13, 10, '  Encrypted (hex): $'
msg_enc_hint    db 13, 10, '  (Select and copy hex above, paste into Decrypt)', 13, 10, '$'
msg_dec_prompt  db 13, 10, '  Enter hex to decrypt:', 13, 10, '  > $'
msg_dec_result  db 13, 10, '  Decrypted: $'

; -- Notes strings --------------------------------------------
msg_note_limit  db 13, 10, '  [Note storage: 3 notes max, 75 chars each]', 13, 10, '$'
msg_note_prompt db 13, 10, '  Enter note (max 75 chars):', 13, 10, '  > $'
msg_note_saved  db 13, 10, '  [OK] Note saved!', 13, 10, '$'
msg_note_full   db 13, 10, '  [!] Note storage full (max 3).', 13, 10, '$'
msg_note_empty  db 13, 10, '  [!] No notes stored yet.', 13, 10, '$'
msg_note_list   db 13, 10, '  Stored Notes:', 13, 10, '$'
msg_note_num1   db 13, 10, '  Note 1: $'
msg_note_num2   db 13, 10, '  Note 2: $'
msg_note_num3   db 13, 10, '  Note 3: $'

; -- General strings ------------------------------------------
msg_newline     db 13, 10, '$'
msg_invalid     db 13, 10, '  [!] Invalid option.', 13, 10, '$'
msg_logout      db 13, 10, '  Logged out.', 13, 10, '$'

; -- Hardcoded default account --------------------------------
; This account always exists. Null (0) marks end of each string.
default_user    db 'admin', 0
default_pass    db '1234', 0

; -- Storage for a registered user (created via Register) -----
; 'dup(0)' fills the space with zeros.
; We allow 20 characters + 1 null terminator = 21 bytes each.
reg_user        db 21 dup(0)
reg_pass        db 21 dup(0)
reg_exists      db 0        ; flag: 0 = no registered user, 1 = one exists

; -- Temporary buffers for login input ------------------------
; These hold what the user types at the login screen,
; before we compare against stored credentials.
input_user      db 21 dup(0)
input_pass      db 21 dup(0)

; -- Note storage — up to 3 notes, 75 chars each -------------
note1           db 76 dup(0)    ; note 1 text  (75 chars + null)
note2           db 76 dup(0)    ; note 2 text
note3           db 76 dup(0)    ; note 3 text
note_count      db 0            ; how many notes saved so far (0, 1, 2, or 3)

; -- Work buffer for encrypt/decrypt input --------------------
work_buf        db 76 dup(0)

; -- Login attempt counter ------------------------------------
attempts        db 3            ; user gets 3 tries before lockout

; -- DOS buffered input buffer --------------------------------
; INT 21h / AH=0Ah needs a special buffer format:
;   Byte 0: maximum characters to accept (we set this)
;   Byte 1: actual characters typed (DOS fills this after the call)
;   Byte 2 onwards: the typed text (no Enter key stored here)
; We reuse this same buffer for all input calls.
; 75 chars max = one safe console line (80 wide screen - prompt space)
dos_inbuf       db 76           ; [0] max = 75 chars + 1 spare
                db 0            ; [1] actual count (DOS writes here)
                db 77 dup(0)    ; [2+] the actual typed characters

; -------------------------------------------------------------
;  CODE SECTION — all procedures live below this line
; -------------------------------------------------------------
.code

; +--------------------------------------------------------------+
; ¦  MAIN — Entry point                                          ¦
; ¦  The program starts here. We set DS to point at our data     ¦
; ¦  segment, then loop showing the welcome screen forever.      ¦
; +--------------------------------------------------------------+
main PROC
    ; DS must point to our .data segment before we can use
    ; any variables. @data is the assembler symbol for that segment.
    mov ax, @data
    mov ds, ax

WELCOME_LOOP:
    call SHOW_WELCOME           ; display the NexLock title + menu
    call READ_CHOICE            ; wait for user to type a digit + Enter
                                ; result comes back in AL

    cmp al, '1'
    je  DO_LOGIN                ; user typed 1 ? go to login
    cmp al, '2'
    je  DO_REGISTER             ; user typed 2 ? go to register
    jmp WELCOME_LOOP            ; anything else ? show menu again

DO_REGISTER:
    call REGISTER_USER
    jmp WELCOME_LOOP            ; after registering, back to welcome

DO_LOGIN:
    call LOGIN                  ; LOGIN returns AL=1 (success) or AL=0 (fail/lock)
    cmp al, 1
    jne WELCOME_LOOP            ; login failed ? back to welcome
    call MAIN_MENU              ; login succeeded ? enter main menu
    jmp WELCOME_LOOP            ; after logout, back to welcome

    ; Note: the two lines below are never reached because of the
    ; jmp above, but they are the proper way to end a DOS program.
    mov ax, 4C00h
    int 21h
main ENDP

; +--------------------------------------------------------------+
; ¦  SHOW_WELCOME                                                ¦
; ¦  Prints the title banner and the Login/Register menu.        ¦
; +--------------------------------------------------------------+
SHOW_WELCOME PROC
    ; INT 21h / AH=09h prints a string. DX must hold the address.
    ; 'lea dx, msg_welcome' loads that address into DX.
    lea dx, msg_welcome
    mov ah, 09h
    int 21h

    lea dx, msg_menu_main
    mov ah, 09h
    int 21h
    ret
SHOW_WELCOME ENDP

; +--------------------------------------------------------------+
; ¦  REGISTER_USER                                               ¦
; ¦  Asks for a new username and password, stores them in        ¦
; ¦  reg_user and reg_pass, sets reg_exists = 1.                 ¦
; +--------------------------------------------------------------+
REGISTER_USER PROC
    ; Print the username prompt, then call READ_STRING.
    ; READ_STRING needs DI = address of the destination buffer.
    lea dx, msg_reg_user
    mov ah, 09h
    int 21h
    lea di, reg_user            ; tell READ_STRING: write into reg_user
    call READ_STRING

    lea dx, msg_reg_pass
    mov ah, 09h
    int 21h
    lea di, reg_pass            ; tell READ_STRING: write into reg_pass
    call READ_STRING

    mov reg_exists, 1           ; mark that a registered user now exists

    lea dx, msg_reg_ok
    mov ah, 09h
    int 21h
    ret
REGISTER_USER ENDP

; +--------------------------------------------------------------+
; ¦  LOGIN                                                       ¦
; ¦  Reads username + password, compares against both accounts.  ¦
; ¦  Returns: AL = 1 (success)  or  AL = 0 (locked/failed)      ¦
; +--------------------------------------------------------------+
LOGIN PROC
    mov attempts, 3             ; reset counter each time login screen opens

LOGIN_TRY:
    ; Read username into input_user
    lea dx, msg_login_user
    mov ah, 09h
    int 21h
    lea di, input_user
    call READ_STRING

    ; Read password into input_pass
    lea dx, msg_login_pass
    mov ah, 09h
    int 21h
    lea di, input_pass
    call READ_STRING

    ; -- Check against hardcoded admin account ----------------
    ; STRCMP takes SI = string1, DI = string2
    ; and returns AL = 1 if they match, AL = 0 if not.
    lea si, default_user
    lea di, input_user
    call STRCMP
    cmp al, 1
    jne CHECK_REGISTERED        ; username didn't match "admin" ? try registered

    ; Username matched "admin" — now check password
    lea si, default_pass
    lea di, input_pass
    call STRCMP
    cmp al, 1
    je  LOGIN_SUCCESS           ; both match ? success

    jmp LOGIN_WRONG             ; username matched but password wrong

    ; -- Check against registered user account ----------------
CHECK_REGISTERED:
    cmp reg_exists, 1
    jne LOGIN_WRONG             ; no registered user exists ? definitely wrong

    lea si, reg_user
    lea di, input_user
    call STRCMP
    cmp al, 1
    jne LOGIN_WRONG             ; registered username doesn't match

    lea si, reg_pass
    lea di, input_pass
    call STRCMP
    cmp al, 1
    je  LOGIN_SUCCESS           ; both match ? success
                                ; (fall through to LOGIN_WRONG if password wrong)

    ; -- Wrong credentials ------------------------------------
LOGIN_WRONG:
    dec attempts                ; use one attempt
    cmp attempts, 0
    je  LOCK_NOW                ; used all 3 ? lock

    ; Print "Wrong credentials. Attempts left: X"
    lea dx, msg_login_fail
    mov ah, 09h
    int 21h
    ; Print the remaining count as a digit
    ; ('0' in ASCII is 48, so adding '0' converts 2 ? '2')
    mov al, attempts
    add al, '0'
    mov dl, al
    mov ah, 02h
    int 21h
    call PRINT_NEWLINE
    jmp LOGIN_TRY               ; let them try again

LOCK_NOW:
    call LOCK_ACCOUNT           ; beep + wait
    mov al, 0                   ; return failure
    ret

LOGIN_SUCCESS:
    lea dx, msg_login_ok
    mov ah, 09h
    int 21h
    mov al, 1                   ; return success
    ret
LOGIN ENDP

; +--------------------------------------------------------------+
; ¦  LOCK_ACCOUNT                                                ¦
; ¦  Plays a beep, prints locked message, waits with a delay     ¦
; ¦  loop, then prints "access restored".                        ¦
; +--------------------------------------------------------------+
LOCK_ACCOUNT PROC
    ; AH=02h prints one character. DL=07h is the ASCII bell (beep).
    mov ah, 02h
    mov dl, 07h
    int 21h

    lea dx, msg_locked
    mov ah, 09h
    int 21h

    ; Delay loop for EMU8086.
    ; The emulator is much slower than real hardware because every
    ; instruction has to be simulated in software. 0FFFFh (65535)
    ; was still too long. 0800h (2048) gives roughly 3-5 seconds
    ; of visible wait in EMU8086 at normal emulation speed.
    ; If it still feels too long, lower 0800h. Too short, raise it.
    mov cx, 0800h               ; count = 2048 iterations
DELAY_LOOP:
    loop DELAY_LOOP             ; LOOP decrements CX and repeats until CX = 0

    lea dx, msg_restored
    mov ah, 09h
    int 21h
    ret
LOCK_ACCOUNT ENDP

; +--------------------------------------------------------------+
; ¦  MAIN_MENU                                                   ¦
; ¦  Shows the 5-option menu and dispatches to the right         ¦
; ¦  procedure. Loops until the user picks Logout (5).           ¦
; +--------------------------------------------------------------+
MAIN_MENU PROC
MENU_LOOP:
    lea dx, msg_main_menu
    mov ah, 09h
    int 21h

    call READ_CHOICE            ; wait for digit + Enter ? AL = the digit

    cmp al, '1'
    je  DO_ENCRYPT
    cmp al, '2'
    je  DO_DECRYPT
    cmp al, '3'
    je  DO_STORE_NOTE
    cmp al, '4'
    je  DO_VIEW_NOTE
    cmp al, '5'
    je  DO_LOGOUT

    ; If we reach here the user typed something invalid
    lea dx, msg_invalid
    mov ah, 09h
    int 21h
    jmp MENU_LOOP

DO_ENCRYPT:
    call ENCRYPT_MSG
    jmp MENU_LOOP
DO_DECRYPT:
    call DECRYPT_MSG
    jmp MENU_LOOP
DO_STORE_NOTE:
    call STORE_NOTE
    jmp MENU_LOOP
DO_VIEW_NOTE:
    call VIEW_NOTE
    jmp MENU_LOOP
DO_LOGOUT:
    lea dx, msg_logout
    mov ah, 09h
    int 21h
    ret                         ; return to main ? back to welcome screen
MAIN_MENU ENDP

; +--------------------------------------------------------------+
; ¦  ENCRYPT_MSG                                                 ¦
; ¦  Reads a message (max 50 chars).                             ¦
; ¦  Encrypts each character: step1 = char + 3  (Caesar cipher) ¦
; ¦                           step2 = step1 XOR 0Ah             ¦
; ¦  Prints each encrypted byte as 2 hex digits (e.g. 6E).      ¦
; ¦  Hex output is used because the raw encrypted bytes can be   ¦
; ¦  control characters that can't be typed or displayed.        ¦
; +--------------------------------------------------------------+
ENCRYPT_MSG PROC
    lea dx, msg_enc_prompt
    mov ah, 09h
    int 21h

    lea di, work_buf            ; READ_STRING will store input here
    call READ_STRING

    lea dx, msg_enc_result
    mov ah, 09h
    int 21h

    lea si, work_buf            ; SI now points to the start of the input
ENC_LOOP:
    mov al, [si]                ; load next character from the string
    cmp al, 0                   ; null terminator? ? we are done
    je  ENC_DONE

    add al, 3                   ; Caesar cipher: shift ASCII value up by 3
    xor al, 0Ah                 ; XOR with key 0Ah (10 in decimal)

    call PRINT_HEX_BYTE         ; print the encrypted byte as "XX"

    ; print a space between hex pairs so it looks like: 6E 0A 2F
    mov dl, ' '
    mov ah, 02h
    int 21h

    inc si                      ; move SI to the next character
    jmp ENC_LOOP

ENC_DONE:
    call PRINT_NEWLINE
    lea dx, msg_enc_hint
    mov ah, 09h
    int 21h
    ret
ENCRYPT_MSG ENDP

; +--------------------------------------------------------------+
; ¦  DECRYPT_MSG                                                 ¦
; ¦  User types the hex output from ENCRYPT_MSG (e.g. 6E 0A 2F) ¦
; ¦  Reads 2 hex characters at a time, skips spaces.            ¦
; ¦  Reverses the cipher: step1 = byte XOR 0Ah                  ¦
; ¦                       step2 = step1 - 3                     ¦
; ¦  Prints the recovered original character.                    ¦
; +--------------------------------------------------------------+
DECRYPT_MSG PROC
    lea dx, msg_dec_prompt
    mov ah, 09h
    int 21h

    lea di, work_buf
    call READ_STRING

    lea dx, msg_dec_result
    mov ah, 09h
    int 21h

    lea si, work_buf
DEC_LOOP:
    mov al, [si]
    cmp al, 0                   ; end of input string?
    je  DEC_DONE

    ; Skip any space characters between hex pairs
    cmp al, ' '
    jne DEC_NOT_SPACE
    inc si
    jmp DEC_LOOP

DEC_NOT_SPACE:
    ; We expect two hex characters here, e.g. '6' and 'E'
    ; Check that a second character exists
    mov bl, [si+1]
    cmp bl, 0
    je  DEC_DONE                ; only 1 char left — incomplete pair, stop

    ; -- Reconstruct the byte from two hex characters ---------
    ; Each hex char represents 4 bits (a "nibble").
    ; High nibble: [si+0], Low nibble: [si+1]
    ; Example: '6' 'E' ? 0110 1110 ? 0x6E

    ; Convert high nibble character to its value (0–15)
    call HEX_CHAR_TO_NIB        ; AL = value of high nibble
    mov cl, 4
    shl al, cl                  ; shift left 4 bits: 0x06 ? 0x60
    mov bh, al                  ; save the shifted high nibble

    ; Convert low nibble character to its value
    mov al, [si+1]
    call HEX_CHAR_TO_NIB        ; AL = value of low nibble (0x0E)
    or  al, bh                  ; combine: 0x60 OR 0x0E = 0x6E ?

    ; -- Reverse the encryption -------------------------------
    xor al, 0Ah                 ; undo the XOR (XOR with same key reverses it)
    sub al, 3                   ; undo the Caesar shift

    ; Print the recovered character
    mov dl, al
    mov ah, 02h
    int 21h

    add si, 2                   ; skip past both hex chars we just processed
    jmp DEC_LOOP

DEC_DONE:
    call PRINT_NEWLINE
    ret
DECRYPT_MSG ENDP

; +--------------------------------------------------------------+
; ¦  PRINT_HEX_BYTE                                              ¦
; ¦  Input:  AL = one byte (0–255)                               ¦
; ¦  Output: prints 2 uppercase hex characters to screen         ¦
; ¦  Example: AL = 0x6E ? prints "6E"                           ¦
; +--------------------------------------------------------------+
PRINT_HEX_BYTE PROC
    mov bh, al                  ; save the full byte so we can use AL freely

    ; -- Print high nibble (top 4 bits) -----------------------
    ; Example: 0x6E ? shift right 4 ? 0x06
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1                   ; four shifts = divide by 16 = get top nibble
    and al, 0Fh                 ; mask to 4 bits just to be safe
    call NIB_TO_CHAR            ; convert 6 ? '6'
    mov dl, al
    mov ah, 02h
    int 21h

    ; -- Print low nibble (bottom 4 bits) ---------------------
    ; Example: 0x6E ? AND with 0x0F ? 0x0E
    mov al, bh                  ; restore original byte
    and al, 0Fh                 ; keep only bottom 4 bits
    call NIB_TO_CHAR            ; convert 14 ? 'E'
    mov dl, al
    mov ah, 02h
    int 21h

    ret
PRINT_HEX_BYTE ENDP

; +--------------------------------------------------------------+
; ¦  NIB_TO_CHAR                                                 ¦
; ¦  Converts a nibble value to its hex ASCII character.         ¦
; ¦  Input:  AL = nibble value (0–15)                            ¦
; ¦  Output: AL = ASCII character ('0'–'9' or 'A'–'F')          ¦
; ¦  Example: AL=6 ? '6',  AL=14 ? 'E'                          ¦
; +--------------------------------------------------------------+
NIB_TO_CHAR PROC
    cmp al, 9
    jle NTC_DIGIT               ; 0–9: just add '0' (ASCII 48)
    add al, 'A' - 10            ; 10?'A', 11?'B', ... 15?'F'
    ret
NTC_DIGIT:
    add al, '0'                 ; 0?'0', 1?'1', ... 9?'9'
    ret
NIB_TO_CHAR ENDP

; +--------------------------------------------------------------+
; ¦  HEX_CHAR_TO_NIB                                             ¦
; ¦  Converts a hex ASCII character to its nibble value.         ¦
; ¦  Input:  AL = '0'-'9', 'A'-'F', or 'a'-'f'                  ¦
; ¦  Output: AL = nibble value (0–15)                            ¦
; ¦  Example: AL='6' ? 6,  AL='E' ? 14,  AL='e' ? 14            ¦
; +--------------------------------------------------------------+
HEX_CHAR_TO_NIB PROC
    ; Handle lowercase: if AL >= 'a', subtract 32 to make uppercase
    cmp al, 'a'
    jl  HCN_UPPER
    sub al, 32
HCN_UPPER:
    cmp al, '9'
    jg  HCN_LETTER
    sub al, '0'                 ; '0'?0, '1'?1 ... '9'?9
    ret
HCN_LETTER:
    sub al, 'A'
    add al, 10                  ; 'A'?10, 'B'?11 ... 'F'?15
    ret
HEX_CHAR_TO_NIB ENDP

; +--------------------------------------------------------------+
; ¦  STORE_NOTE                                                  ¦
; ¦  Saves typed text into note1, note2, or note3 depending on   ¦
; ¦  how many notes are already saved (tracked by note_count).   ¦
; ¦  Maximum 3 notes, 50 characters each.                        ¦
; +--------------------------------------------------------------+
STORE_NOTE PROC
    ; Check if all 3 slots are taken
    cmp note_count, 3
    jl  SN_OK                   ; less than 3 saved ? there is room

    lea dx, msg_note_full
    mov ah, 09h
    int 21h
    ret

SN_OK:
    ; Remind the user of the limits before they type
    lea dx, msg_note_limit
    mov ah, 09h
    int 21h

    lea dx, msg_note_prompt
    mov ah, 09h
    int 21h

    ; Pick destination buffer based on how many notes exist
    ; note_count=0 ? write into note1
    ; note_count=1 ? write into note2
    ; note_count=2 ? write into note3
    mov al, note_count
    cmp al, 0
    je  SN_USE1
    cmp al, 1
    je  SN_USE2
    lea di, note3               ; note_count must be 2
    jmp SN_READ
SN_USE1:
    lea di, note1
    jmp SN_READ
SN_USE2:
    lea di, note2

SN_READ:
    call READ_STRING            ; read input into whichever buffer DI points to

    inc note_count              ; one more note is now saved

    lea dx, msg_note_saved
    mov ah, 09h
    int 21h
    ret
STORE_NOTE ENDP

; +--------------------------------------------------------------+
; ¦  VIEW_NOTE                                                   ¦
; ¦  Displays all saved notes directly. Since each note is       ¦
; ¦  max 100 chars, the full text fits on one line — no need     ¦
; ¦  to select by number first.                                  ¦
; +--------------------------------------------------------------+
VIEW_NOTE PROC
    cmp note_count, 0
    je  VN_EMPTY                ; no notes ? show empty message

    lea dx, msg_note_list
    mov ah, 09h
    int 21h

    ; Always show Note 1 (at least 1 exists if we are here)
    lea dx, msg_note_num1
    mov ah, 09h
    int 21h
    lea si, note1
    call PRINT_STR_SI
    call PRINT_NEWLINE

    ; Show Note 2 only if it exists
    cmp note_count, 2
    jl  VN_DONE
    lea dx, msg_note_num2
    mov ah, 09h
    int 21h
    lea si, note2
    call PRINT_STR_SI
    call PRINT_NEWLINE

    ; Show Note 3 only if it exists
    cmp note_count, 3
    jl  VN_DONE
    lea dx, msg_note_num3
    mov ah, 09h
    int 21h
    lea si, note3
    call PRINT_STR_SI
    call PRINT_NEWLINE

VN_DONE:
    ret

VN_EMPTY:
    lea dx, msg_note_empty
    mov ah, 09h
    int 21h
    ret
VIEW_NOTE ENDP

; +--------------------------------------------------------------+
; ¦  PRINT_STR_SI                                                ¦
; ¦  Prints a null-terminated string starting at [SI].           ¦
; ¦  Stops when it finds a 0 byte.                               ¦
; +--------------------------------------------------------------+
PRINT_STR_SI PROC
PSI_LOOP:
    mov al, [si]                ; load next character
    cmp al, 0                   ; null terminator?
    je  PSI_DONE
    mov dl, al
    mov ah, 02h
    int 21h                     ; print the character
    inc si                      ; move to next character
    jmp PSI_LOOP
PSI_DONE:
    ret
PRINT_STR_SI ENDP

; +--------------------------------------------------------------+
; ¦  READ_STRING                                                 ¦
; ¦  Reads a line of text from the keyboard into [DI].           ¦
; ¦  Uses INT 21h / AH=0Ah (DOS buffered input).                 ¦
; ¦  This is reliable: it consumes the Enter key so no stray     ¦
; ¦  characters are left in the buffer to confuse the next read. ¦
; ¦  Caller must set DI = address of destination buffer first.   ¦
; +--------------------------------------------------------------+
READ_STRING PROC
    push si                     ; save SI and CX — we will use them
    push cx                     ; and we must restore them before returning

    ; Reset the count byte (byte 1) of dos_inbuf to 0
    mov byte ptr [dos_inbuf+1], 0

    ; AH=0Ah reads text until Enter.
    ; DX must point to dos_inbuf (the special format buffer).
    lea dx, dos_inbuf
    mov ah, 0Ah
    int 21h
    ; After this call:
    ;   dos_inbuf[1] = number of characters typed (not counting Enter)
    ;   dos_inbuf[2..] = the actual text

    ; Copy the typed text from dos_inbuf into the caller's buffer [DI]
    lea si, dos_inbuf+2         ; SI = start of typed text
    mov cl, [dos_inbuf+1]       ; CL = how many characters were typed
    mov ch, 0                   ; CX = full count (CH=0, CL=count)

    cmp cx, 0
    je  RS_EMPTY                ; nothing was typed ? just null-terminate

RS_COPY:
    mov al, [si]                ; read one character from dos_inbuf
    mov [di], al                ; write it to the caller's buffer
    inc si
    inc di
    loop RS_COPY                ; repeat CX times (LOOP decrements CX)

RS_EMPTY:
    mov byte ptr [di], 0        ; write null terminator at end of string

    call PRINT_NEWLINE          ; move cursor to next line

    pop cx                      ; restore registers we saved at the top
    pop si
    ret
READ_STRING ENDP

; +--------------------------------------------------------------+
; ¦  STRCMP                                                      ¦
; ¦  Compares two null-terminated strings character by character.¦
; ¦  Input:  SI = address of string 1                            ¦
; ¦          DI = address of string 2                            ¦
; ¦  Output: AL = 1 if strings are equal, AL = 0 if not          ¦
; ¦  SI and DI are restored before returning (push/pop).         ¦
; +--------------------------------------------------------------+
STRCMP PROC
    push si                     ; save SI and DI so the caller's
    push di                     ; values are not disturbed

SC_LOOP:
    mov al, [si]                ; load character from string 1
    mov bl, [di]                ; load character from string 2
    cmp al, bl
    jne SC_NOT_EQUAL            ; characters differ ? not equal

    cmp al, 0                   ; both chars were 0 (null terminator)?
    je  SC_EQUAL                ; yes ? we reached the end ? strings are equal

    inc si                      ; move to next character in string 1
    inc di                      ; move to next character in string 2
    jmp SC_LOOP

SC_EQUAL:
    mov al, 1                   ; return value: 1 = equal
    jmp SC_EXIT
SC_NOT_EQUAL:
    mov al, 0                   ; return value: 0 = not equal
SC_EXIT:
    pop di                      ; restore DI and SI
    pop si
    ret
STRCMP ENDP

; +--------------------------------------------------------------+
; ¦  READ_CHOICE                                                 ¦
; ¦  Reads a full line (requires Enter) and returns the first    ¦
; ¦  character typed in AL.                                      ¦
; ¦  Using AH=0Ah here (instead of AH=01h) is important:        ¦
; ¦  it fully consumes the Enter key, so READ_STRING never sees  ¦
; ¦  a leftover Enter from a menu selection.                     ¦
; +--------------------------------------------------------------+
READ_CHOICE PROC
    mov byte ptr [dos_inbuf+1], 0   ; reset count byte

    lea dx, dos_inbuf
    mov ah, 0Ah
    int 21h                     ; read line; Enter is consumed here

    call PRINT_NEWLINE

    ; Return the first character the user typed
    mov al, [dos_inbuf+2]       ; dos_inbuf+2 is where text starts
    cmp byte ptr [dos_inbuf+1], 0
    jne RC_DONE
    mov al, 0                   ; user pressed Enter without typing anything
RC_DONE:
    ret
READ_CHOICE ENDP

; +--------------------------------------------------------------+
; ¦  PRINT_NEWLINE                                               ¦
; ¦  Prints a carriage return + line feed (moves to next line).  ¦
; +--------------------------------------------------------------+
PRINT_NEWLINE PROC
    lea dx, msg_newline         ; msg_newline = 13, 10, '$'
    mov ah, 09h
    int 21h
    ret
PRINT_NEWLINE ENDP

END main