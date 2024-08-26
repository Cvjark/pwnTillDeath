# pwnTillDeath
折腾着玩~

# 学习库
- [pwn-notes](https://github.com/ir0nstone/pwn-noteshttps://github.com/ir0nstone/pwn-notes)
- [sixStars CTF](https://github.com/sixstars)
- [ropemporium](https://ropemporium.com/)    # focus on ROP topic
- [readTeamNote: binary-exploitation](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation)

# fmtString
- [x] x64: hackIM19/pwn/babypwn Format String, Signed/Unsigned bug, fmt string libc infoleak with %s, LD_PRELOAD, id remote libc file, get scanf not to write over a value  有意思的题
- [x] x86: backdoorctf/bbpwn Format String, got overwrite, system imported function
- [ ] x86: tokyowesterns16/pwn/greeting Format String, .fini_array write to cause loop back, overwrite got address with plt system
- [ ] x86: tu19/vulnmath/ use fmt string bug to get libc infoleak, then got overwrite

# Stack
- [x] x86: tu19/thefirst simple buffer overflow with gets to call a different function    简单题
- [x] Csaw13/pwn/exploit1 overwrite variable on stack    简单题
- [x] x64: Csaw18/pwn/get_it simple buffer overflow hidword on the stack  简单题
- [x] x64: googlequals17/pwn/wiki vsyscall, PIE, buffer overflow, no verbose output  特殊滑板，观测关键 vuln 点的逻辑
- [ ] sixstarctf2018_babystack, stack overflow. ROP、put_plt to leak。problems: 新线程对应的 canary 偏移计算
- [ ] TokyoWestern18_pwn_load ROP，stack overflow，fd assign。
