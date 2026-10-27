# Hex-Rays F5 输出（番茄 Reading 7.4.1）

**方法说明**：`Reading` 单文件 508 MB、ObjC 类 78,911 个，直接 `idat -A` 全量导入在 16 GB 机器上不可行（实测：卡在 ObjC 解析 >750 s，`.id0` 2.1 GB / `.id1` 1.9 GB；`idalib` 无分析加载 `open_database` 亦 >600 s 未返回）。

改为**雕刻子二进制**：按目标函数取 ±4 KB/±1 KB 窗口，包进最小 ELF64（`PT_LOAD` 的 `p_vaddr` 保持原虚拟地址），用 `idalib.open_database(path, run_auto_analysis=False)` + `ida_funcs.add_func` + `ida_hexrays.decompile` 逐函数反编译，每次 ~1 秒。

**读法**：跨切片的外部调用显示为 `MEMORY[0x地址]()`，`JUMPOUT(0x地址)` 是尾调用；这不是反编译失败，是切片外的目标不可见。地址与原始二进制一致。

---

===== dec_v1 @ 0x109f8b83c =====
__int64 __fastcall sub_109F8B83C(__int64 result, __int64 a2, int a3)
{
  signed int v3; // w9
  signed int v4; // w10
  int v5; // w11
  unsigned __int64 v6; // t2
  int v7; // w10

  if ( a3 >= 4 )
  {
    v4 = 0;
    v5 = 4;
    do
    {
      v3 = v5;
      HIDWORD(v6) = *(_DWORD *)(a2 + v4) ^ 0xDEADBEEF;
      LODWORD(v6) = HIDWORD(v6);
      *(_DWORD *)(result + v4) = v6 >> 23;
      v5 = ((2 * v5) & 8) + (v5 ^ 4);
      v4 = v3;
    }
    while ( v5 <= a3 );
  }
  else
  {
    v3 = 0;
  }
  if ( v3 < a3 )
  {
    v7 = 0;
    do
    {
      *(_BYTE *)(result + v3) = *(_BYTE *)(a2 + v3) ^ (0xDEADBEEF >> v7);
      v3 = (v3 ^ 0xFFFFFFFE) + ((2 * v3) | 2) + 1;
      v7 += 8;
    }
    while ( v3 < a3 );
  }
  return result;
}


===== dec_v2_island @ 0x109f778f4 =====
None

===== sandbox_statfs93 @ 0x10a09f79c =====
void sub_10A09F79C()
{
  __int64 v0; // x19
  __int64 v1; // x0
  __int64 v2; // x0
  __int64 v3; // x0
  char v4; // zf

  v0 = 0;
  if ( (MEMORY[0x109E1723C]() & 1) != 0 )
  {
    while ( v0 != 344 )
    {
      v1 = MEMORY[0x109E3C620]();
      v0 += 8;
      if ( !(_DWORD)v1 )
        goto LABEL_11;
    }
  }
  else
  {
    while ( v0 != 400 )
    {
      v1 = MEMORY[0x109E3C620]();
      v0 += 8;
      if ( !(_DWORD)v1 )
        goto LABEL_11;
    }
  }
  MEMORY[0x109E3C614]();
  v2 = MEMORY[0x109E3C608](0x1136AD0D6LL, 514);
  if ( (MEMORY[0x111A9531C](v2) & 0x80000000) != 0 )
  {
    v1 = 1;
  }
  else
  {
    MEMORY[0x111A93210]();
    MEMORY[0x111A959AC](0x1136AD0D6LL);
    v1 = 0;
  }
LABEL_11:
  v3 = MEMORY[0x109E10458](v1);
  if ( !v4 )
    MEMORY[0x107C24CC4](v3);
  JUMPOUT(0x109E28840LL);
}


===== isEnvAbnormal @ 0x10a09f728 =====
void __fastcall sub_10A09F728(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9)
{
  __int64 v9; // x29
  __int64 v10; // x30

  if ( MEMORY[0x11D7766F8] != -1 )
  {
    *(&a9 - 2) = v9;
    *(&a9 - 1) = v10;
    MEMORY[0x109E3C5D8]();
  }
  JUMPOUT(0x109E3C5CCLL);
}

===== pred_inject_substr @ 0x1083e1854 =====
void sub_1083E1854()
{
  __int64 v0; // x0
  __int64 v1; // x0
  __int64 v2; // x22
  __int64 v3; // x1
  __int64 v4; // x21

  v0 = MEMORY[0x109E0CA54]();
  v1 = MEMORY[0x109E41180](v0);
  v2 = 0;
  v4 = *(_QWORD *)(v3 + 16);
  while ( 1 )
  {
    if ( v2 == 40 )
      goto LABEL_7;
    if ( v4 )
    {
      v1 = MEMORY[0x109EDFBC0](v1, *(_QWORD *)(v2 + 0x119055038LL));
      if ( v1 )
        break;
    }
    v2 += 8;
  }
  MEMORY[0x109EDD9A8]();
LABEL_7:
  JUMPOUT(0x109E0DB6CLL);
}


===== rule_builder_CF @ 0x10185adf8 =====
__int64 __fastcall sub_10185ADF8(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9,
        __int64 a10,
        __int64 a11,
        __int64 a12,
        int a13,
        __int64 a14,
        __int64 a15,
        __int16 a16,
        __int64 a17,
        __int64 a18,
        int a19,
        __int64 a20,
        __int64 a21,
        __int64 a22,
        char a23,
        __int64 a24,
        int a25,
        __int64 a26,
        int a27,
        __int64 a28,
        __int64 a29,
        char a30,
        __int64 a31,
        char a32,
        int a33,
        __int64 *a34,
        int a35,
        int a36,
        __int64 *a37,
        int a38,
        int a39,
        __int64 *a40,
        int a41,
        int a42,
        __int64 *a43,
        int a44,
        int a45,
        __int64 *a46,
        int a47,
        int a48,
        __int64 *a49,
        int a50,
        int a51,
        __int64 *a52,
        int a53,
        int a54,
        __int64 *a55,
        int a56,
        int a57,
        __int64 *a58,
        int a59,
        int a60,
        __int64 *a61,
        int a62,
        int a63)
{
  __int64 *a64; // [xsp+1B8h] [xbp+1B8h]
  int a65; // [xsp+1C0h] [xbp+1C0h]
  int a66; // [xsp+1C8h] [xbp+1C8h]
  __int64 *a67; // [xsp+1D0h] [xbp+1D0h]
  int a68; // [xsp+1D8h] [xbp+1D8h]
  __int64 a69; // [xsp+1E0h] [xbp+1E0h] BYREF
  __int64 a70; // [xsp+1E8h] [xbp+1E8h]
  char a71; // [xsp+1F0h] [xbp+1F0h]
  __int64 a72; // [xsp+1F8h] [xbp+1F8h] BYREF
  __int64 result; // x0

  a72 = 0x112F158F7LL;
  STACK[0x200] = (unsigned __int64)&unk_10185A9B0;
  LOBYTE(STACK[0x208]) = 0;
  STACK[0x210] = 0x112F158FBLL;
  STACK[0x218] = (unsigned __int64)&unk_10185A9DC;
  LOBYTE(STACK[0x220]) = 0;
  STACK[0x228] = 0x112F158FFLL;
  STACK[0x230] = (unsigned __int64)&unk_10185AA14;
  LOBYTE(STACK[0x238]) = 0;
  STACK[0x240] = 0x112F15903LL;
  STACK[0x248] = (unsigned __int64)&unk_10185AA60;
  LOBYTE(STACK[0x250]) = 0;
  STACK[0x258] = 0x112F15907LL;
  STACK[0x260] = (unsigned __int64)&unk_10185AA98;
  LOBYTE(STACK[0x268]) = 0;
  STACK[0x270] = 0x112F1590BLL;
  STACK[0x278] = (unsigned __int64)&unk_10185AAF0;
  LOBYTE(STACK[0x280]) = 0;
  STACK[0x288] = 0x112F1590FLL;
  STACK[0x290] = (unsigned __int64)&unk_10185AB58;
  LOBYTE(STACK[0x298]) = 0;
  STACK[0x2A0] = 0x112F15913LL;
  STACK[0x2A8] = (unsigned __int64)&unk_10185ABB0;
  LOBYTE(STACK[0x2B0]) = 0;
  STACK[0x2B8] = 0x112F15917LL;
  STACK[0x2C0] = (unsigned __int64)&unk_10185ABE8;
  LOBYTE(STACK[0x2C8]) = 0;
  STACK[0x2D0] = 0x112F1591BLL;
  STACK[0x2D8] = (unsigned __int64)&unk_10185AC70;
  LOBYTE(STACK[0x2E0]) = 0;
  STACK[0x2E8] = 0x112F1591FLL;
  STACK[0x2F0] = (unsigned __int64)&unk_10185ACBC;
  LOBYTE(STACK[0x2F8]) = 0;
  STACK[0x300] = 0x112F15923LL;
  STACK[0x308] = (unsigned __int64)&unk_10185ACF4;
  LOBYTE(STACK[0x310]) = 0;
  STACK[0x318] = 0x112F15927LL;
  STACK[0x320] = (unsigned __int64)&unk_10185AD2C;
  LOBYTE(STACK[0x328]) = 0;
  STACK[0x330] = 0x112F1592BLL;
  STACK[0x338] = (unsigned __int64)&unk_10185AD68;
  LOBYTE(STACK[0x340]) = 0;
  a69 = 0x112F158F4LL;
  a70 = 0x11D45C5F0LL;
  a71 = 0;
  a31 = 0xB01020902030600LL;
  a32 = 5;
  LOWORD(a33) = 1618;
  BYTE2(a33) = 12;
  a34 = &a31;
  a35 = 3;
  a29 = 0xE00030B02050601LL;
  a30 = 2;
  LOWORD(a36) = -430;
  BYTE2(a36) = 10;
  a37 = &a29;
  a38 = 3;
  LODWORD(a28) = 394753;
  WORD2(a28) = 1036;
  LOWORD(a39) = 1618;
  BYTE2(a39) = 7;
  a40 = &a28;
  a41 = 2;
  a26 = 0xE02020C03060600LL;
  a27 = 85131525;
  LOWORD(a42) = 1362;
  BYTE2(a42) = 18;
  a43 = &a26;
  a44 = 4;
  a24 = 0xC01050702010603LL;
  a25 = 118554629;
  LOWORD(a45) = 3410;
  BYTE2(a45) = 2;
  a46 = &a24;
  a47 = 4;
  a22 = 0x17020C0B00050601LL;
  a23 = 1;
  LOWORD(a48) = 1362;
  BYTE2(a48) = 28;
  a49 = &a22;
  a50 = 3;
  a20 = 0x1302070C00050704LL;
  LODWORD(a21) = 51905285;
  WORD2(a21) = 6913;
  BYTE6(a21) = 5;
  LOWORD(a51) = 3410;
  BYTE2(a51) = 18;
  a52 = &a20;
  a53 = 5;
  a18 = 0x18030C0C00050701LL;
  a19 = 52232709;
  LOWORD(a54) = -1454;
  BYTE2(a54) = 7;
  a55 = &a18;
  a56 = 4;
  LODWORD(a17) = 18089728;
  WORD2(a17) = 1307;
  LOWORD(a57) = 4690;
  BYTE2(a57) = 5;
  a58 = &a17;
  a59 = 2;
  a14 = 0xA02050503050004LL;
  a15 = 0x5051501060F0005LL;
  a16 = 1562;
  LOWORD(a60) = -5550;
  BYTE2(a60) = 8;
  a61 = &a14;
  a62 = 6;
  a12 = 0x1502051001100003LL;
  a13 = 102367237;
  LOWORD(a63) = -4526;
  BYTE2(a63) = 4;
  a64 = &a12;
  a65 = 4;
  LODWORD(a11) = 17170432;
  WORD2(a11) = 6662;
  LOWORD(a66) = 1874;
  BYTE2(a66) = 28;
  a67 = &a11;
  a68 = 2;
  MEMORY[0x11D45C600] = MEMORY[0x1019A0374](0x11D096BA0LL, 1283, &STACK[0x348], 0, &a72, 14, &a69, 1);
  result = MEMORY[0x107C1519C]();
  MEMORY[0x11D45C608] = result;
  return result;
}


===== CF0_checker @ 0x10185a9b0 =====
__int64 __fastcall sub_10185A9B0(__int64 a1)
{
  unsigned int v2; // w0

  v2 = MEMORY[0x107C1516C]();
  return MEMORY[0x1019A08F0](a1, 6, v2);
}


===== vm_get @ 0x1019a08e4 =====
__int64 __fastcall sub_1019A08E4(__int64 a1, unsigned int a2)
{
  return *(_QWORD *)(a1 + 8LL * a2 + 24688);
}


===== vm_set @ 0x1019a08f0 =====
__int64 __fastcall sub_1019A08F0(__int64 result, unsigned int a2, __int64 a3)
{
  *(_QWORD *)(result + 8LL * a2 + 24688) = a3;
  return result;
}


===== isJailBreak @ 0x1074b6ff4 =====
void sub_1074B6FF4()
{
  MEMORY[0x109E0C578]();
  if ( (MEMORY[0x107C07FB8]() & 1) != 0 || (MEMORY[0x109E121CC]() & 1) != 0 )
    JUMPOUT(0x109E2A32CLL);
  MEMORY[0x109E0FE48]();
  JUMPOUT(0x107C07FB8LL);
}


===== hasJailBreakFiles @ 0x1074b7034 =====
void sub_1074B7034()
{
  int v0; // w28
  __int64 v1; // x0
  __int64 v2; // x0
  __int64 v3; // x0
  __int64 v4; // x8
  __int64 v5; // x24
  __int64 v6; // x0
  __int64 v7; // x0
  char v8; // cf
  char v9; // zf
  __int64 v10; // x0
  __int64 v11; // x0
  __int64 v12; // x0
  __int64 v13; // x0
  __int64 v14; // x0
  __int64 v15; // x0
  __int64 v16; // x0
  __int64 v17; // x0

  v1 = MEMORY[0x109E0DFCC]();
  v2 = ((__int64 (__fastcall *)(__int64))unk_1074B7374)(v1);
  v3 = ((__int64 (__fastcall *)(__int64))unk_1074B7368)(v2);
  do
  {
    v5 = v4;
    v6 = MEMORY[0x109E4D904](v3);
    v7 = ((__int64 (__fastcall *)(__int64))unk_1074B738C)(v6);
    if ( !(!v9 & v8) )
      break;
    v10 = ((__int64 (__fastcall *)(__int64))unk_1074B7358)(v7);
    v11 = MEMORY[0x107C07FB8](v10);
    MEMORY[0x107C0819C](v11);
    v12 = MEMORY[0x109EC8D70]();
    v13 = MEMORY[0x107C07FB8](v12);
    v14 = MEMORY[0x107C0819C](v13);
    v15 = MEMORY[0x106D5DECC](v14);
    v16 = MEMORY[0x107C07FB8](v15);
    v17 = MEMORY[0x109E2CA14](v16);
    v3 = MEMORY[0x109E11424](v17);
    v4 = v5 + 1;
  }
  while ( !v0 );
  JUMPOUT(0x109E0F4B8LL);
}


===== sysctl_caller @ 0x106c873c4 =====
void sub_106C873C4()
{
  __int64 v0; // x29
  __int64 v1; // x0
  int v2; // w0
  __int64 v3; // x0
  __int64 v4; // x0
  long double v5; // q0
  long double v6; // q0
  __int64 v7; // x0
  char v8; // zf

  v1 = MEMORY[0x109E11E0C]();
  v2 = MEMORY[0x107C11A00](v1);
  *(_QWORD *)(v0 - 40) = MEMORY[0x112D0BA38];
  *(_DWORD *)(v0 - 32) = 1;
  *(_DWORD *)(v0 - 28) = v2;
  MEMORY[0x109EE5D10]();
  v3 = MEMORY[0x109E73FC0](v0 - 40);
  v4 = MEMORY[0x109E3B0D8](v3);
  *(_QWORD *)&v5 = 0;
  if ( !(_DWORD)v4 )
  {
    v6 = MEMORY[0x109EE5CEC](0.0);
    v4 = MEMORY[0x109E3E7AC](v6);
  }
  v7 = MEMORY[0x109E10174](v4, v5);
  if ( !v8 )
    MEMORY[0x1007950E8](v7);
  JUMPOUT(0x109E3E7A0LL);
}


===== headerInfo @ 0x10a09edbc =====
void sub_10A09EDBC()
{
  __int64 v0; // x26
  __int64 v1; // x22
  __int64 v2; // x0
  __int64 v3; // x0
  __int64 v4; // x19
  __int64 v5; // x21
  __int64 v6; // x0
  __int64 v7; // x0
  __int64 v8; // x20
  __int64 v9; // x0
  __int64 v10; // x0
  __int64 v11; // x0
  __int64 v12; // x0
  __int64 v13; // x0
  __int64 v14; // x0
  __int64 v15; // x0
  __int64 v16; // x0
  __int64 v17; // x0
  __int64 v18; // x0
  __int64 v19; // x0
  __int64 v20; // x0
  __int64 v21; // x0
  __int64 v22; // x0
  __int64 v23; // x0
  __int64 v24; // x0
  __int64 v25; // x0
  __int64 v26; // x0
  __int64 v27; // x0
  __int64 v28; // x0
  __int64 v29; // x0
  __int64 v30; // x0
  __int64 v31; // x0
  __int64 v32; // x0
  __int64 v33; // x0
  __int64 v34; // x0
  __int64 v35; // x0
  __int64 v36; // x0
  __int64 v37; // x0
  __int64 v38; // x0
  __int64 v39; // x0
  __int64 v40; // x0
  __int64 v41; // x0
  __int64 v42; // x0
  __int64 v43; // x0
  __int64 v44; // x0
  __int64 v45; // x0
  __int64 v46; // x0
  __int64 v47; // x0
  __int64 v48; // x0
  __int64 v49; // x0
  __int64 v50; // x0
  __int64 v51; // x0
  __int64 v52; // x0
  __int64 v53; // x0
  __int64 v54; // x0
  __int64 v55; // x0
  __int64 v56; // x0
  __int64 v57; // x0
  __int64 v58; // x0
  __int64 v59; // x0
  __int64 v60; // x0
  __int64 v61; // x0
  __int64 v62; // x0
  __int64 v63; // x0
  __int64 v64; // x0
  __int64 v65; // x0
  __int64 v66; // x0
  __int64 v67; // x0
  __int64 v68; // x0
  __int64 v69; // x0
  __int64 v70; // x0
  __int64 v71; // x0
  __int64 v72; // x0
  __int64 v73; // x0
  __int64 v74; // x0
  __int64 v75; // x0
  __int64 v76; // x0
  __int64 v77; // x0
  __int64 v78; // x0
  __int64 v79; // x0
  __int64 v80; // x0
  __int64 v81; // x0
  __int64 v82; // x0
  __int64 v83; // x0
  __int64 v84; // x0
  __int64 v85; // x0
  __int64 v86; // x0
  __int64 v87; // x0
  __int64 v88; // x0
  __int64 v89; // x0
  __int64 v90; // x0
  __int64 v91; // x0
  __int64 v92; // x0
  __int64 v93; // x0
  __int64 v94; // x0
  __int64 v95; // x0
  __int64 v96; // x0
  __int64 v97; // x0
  __int64 v98; // x0
  __int64 v99; // x0
  __int64 v100; // x0
  __int64 v101; // x0
  __int64 v102; // x0
  __int64 v103; // x0
  __int64 v104; // x0
  __int64 v105; // x0
  __int64 v106; // x0
  __int64 v107; // x0
  __int64 v108; // x0
  __int64 v109; // x0
  __int64 v110; // x0
  __int64 v111; // x0
  __int64 v112; // x0
  __int64 v113; // x0
  __int64 v114; // x0
  __int64 v115; // x0
  __int64 v116; // x0
  __int64 v117; // x0
  __int64 v118; // x0
  __int64 v119; // x0
  __int64 v120; // x0
  __int64 v121; // x0
  __int64 v122; // x0
  __int64 v123; // x0
  __int64 v124; // x0
  __int64 v125; // x0
  __int64 v126; // x0
  __int64 v127; // x0
  __int64 v128; // x0
  __int64 v129; // x0
  __int64 v130; // x0
  __int64 v131; // x0
  __int64 v132; // x0
  __int64 v133; // x0
  __int64 v134; // x0
  __int64 v135; // x0
  __int64 v136; // x0
  __int64 v137; // x0
  __int64 v138; // x0
  __int64 v139; // x0
  __int64 v140; // x0
  __int64 v141; // x0
  __int64 v142; // x0
  __int64 v143; // x0
  __int64 v144; // x0
  __int64 v145; // x0
  __int64 v146; // x0
  __int64 v147; // x0
  __int64 v148; // x0
  __int64 v149; // x0
  __int64 v150; // x0
  __int64 v151; // x0
  __int64 v152; // x0
  __int64 v153; // x0
  __int64 v154; // x0
  __int64 v155; // x0
  __int64 v156; // x0
  __int64 v157; // x0
  __int64 v158; // x0
  __int64 v159; // x0
  __int64 v160; // x0
  __int64 v161; // x0
  __int64 v162; // x0
  __int64 v163; // x0
  __int64 v164; // x0
  __int64 v165; // x0
  __int64 v166; // x0
  __int64 v167; // x0
  __int64 v168; // x0
  __int64 v169; // x0
  __int64 v170; // x0
  __int64 v171; // x0
  __int64 v172; // x0
  __int64 v173; // x0
  __int64 v174; // x0
  __int64 v175; // x0
  __int64 v176; // x0
  __int64 v177; // x0
  __int64 v178; // x0
  __int64 v179; // x0
  __int64 v180; // x0
  __int64 v181; // x0
  __int64 v182; // x0
  __int64 v183; // x8
  __int64 v184; // x28
  __int64 v185; // x0
  __int64 v186; // x0
  __int64 v187; // x0
  __int64 v188; // x0
  __int64 v189; // x0
  __int64 v190; // x0
  __int64 v191; // x0
  __int64 v192; // x0
  __int64 v193; // x0
  __int64 v194; // x0
  __int64 v195; // x0
  __int64 v196; // x0
  __int64 v197; // x0
  __int64 v198; // x0
  __int64 v199; // x0
  __int64 v200; // x0
  unsigned __int64 i; // x25
  unsigned __int64 v202; // x0
  __int64 v203; // x0
  __int64 v204; // x0
  __int64 v205; // x0
  __int64 v206; // x0
  __int64 v207; // x0
  __int64 v208; // x0
  __int64 v209; // x0
  __int64 v210; // x0
  __int64 v211; // x0
  __int64 v212; // x0
  __int64 v213; // x0
  __int64 v214; // x0
  __int64 v215; // x0
  __int64 v216; // x0
  __int64 v217; // x0
  __int64 v218; // x0
  __int64 v219; // x0
  __int64 v220; // x0
  __int64 v221; // x0
  __int64 v222; // x0
  __int64 v223; // x0
  __int64 v224; // x0
  __int64 v225; // x0
  __int64 v226; // x0
  __int64 v227; // x0
  __int64 v228; // x0
  __int64 v229; // x0
  __int64 v230; // x0
  __int64 v231; // x0
  __int64 v232; // x0
  __int64 v233; // x0
  __int64 v234; // x0
  __int64 v235; // x0
  __int64 v236; // x0
  __int64 v237; // x0
  __int64 v238; // x0
  __int64 v239; // x0
  __int64 v240; // x0
  __int64 v241; // x0
  __int64 v242; // x0
  __int64 v243; // x0
  __int64 v244; // x0
  __int64 v245; // x0
  __int64 v246; // x0
  __int64 v247; // x0
  __int64 v248; // x0
  __int64 v249; // x0
  __int64 v250; // x0
  __int64 v251; // x0
  __int64 v252; // x0
  __int64 v253; // x0
  __int64 v254; // x0
  __int64 v255; // x0
  __int64 v256; // x0
  __int64 v257; // x0
  __int64 v258; // x0
  __int64 v259; // x0
  __int64 v260; // x0
  __int64 v261; // x0
  __int64 v262; // x0
  __int64 v263; // x0
  __int64 v264; // x0
  __int64 v265; // x22
  __int64 v266; // x0
  __int64 v267; // x0
  __int64 v268; // x0
  __int64 v269; // x0
  __int64 v270; // x0
  __int64 v271; // x0
  __int64 v272; // x0
  __int64 v273; // x0
  __int64 v274; // x0
  __int64 v275; // x0
  __int64 v276; // x0
  __int64 v277; // x0
  __int64 v278; // x0
  __int64 v279; // x0
  __int64 v280; // x0
  __int64 v281; // x0
  __int64 v282; // x0
  __int64 v283; // x0
  __int64 v284; // x0
  __int64 v285; // x0
  __int64 v286; // x0
  __int64 v287; // x0
  __int64 v288; // x0
  __int64 v289; // x0
  __int64 v290; // x0
  __int64 v291; // x0
  __int64 v292; // x0
  __int64 v293; // x0
  __int64 v294; // x0
  __int64 v295; // x0
  __int64 v296; // x0
  __int64 v297; // x0
  __int64 v298; // x0
  __int64 v299; // x0
  __int64 v300; // x0
  __int64 v301; // x21
  __int64 v302; // x0
  __int64 v303; // x0
  __int64 v304; // x22
  __int64 v305; // x0
  __int64 v306; // x23
  __int64 v307; // x0
  __int64 v308; // x28
  __int64 v309; // x0
  __int64 v310; // x0
  __int64 v311; // x0
  __int64 v312; // x0
  __int64 v313; // x0
  __int64 v314; // x0
  __int64 v315; // x0
  __int64 v316; // x0
  __int64 v317; // x0
  __int64 v318; // x0
  __int64 v319; // x0
  __int64 v320; // x0
  __int64 v321; // x0
  __int64 v322; // x0
  __int64 v323; // x0
  __int64 v324; // x0
  __int64 v325; // x0
  __int64 v326; // x0
  __int64 v327; // x0
  __int64 v328; // x0
  __int64 v329; // [xsp+28h] [xbp+28h]
  __int64 v330; // [xsp+30h] [xbp+30h]

  v1 = MEMORY[0x109E0DFCC]();
  v2 = MEMORY[0x109E23DAC]();
  v3 = MEMORY[0x111A95148](v2);
  v4 = MEMORY[0x111A951FC](v3);
  v5 = MEMORY[0x11C272BF8];
  v6 = MEMORY[0x109E143C8]();
  v7 = MEMORY[0x111A95148](v6);
  MEMORY[0x111A951FC](v7);
  v8 = MEMORY[0x11C1A58A0];
  v9 = MEMORY[0x111A95148]();
  MEMORY[0x111A951FC](v9);
  v10 = MEMORY[0x109E3C5BC]();
  v11 = MEMORY[0x109E143A4](v10);
  v12 = MEMORY[0x109E0EBFC](v11);
  if ( v0 )
  {
    v13 = MEMORY[0x109E143C8](v12);
    v14 = MEMORY[0x111A95148](v13);
    v15 = MEMORY[0x111A951FC](v14);
    v16 = MEMORY[0x109E2BF74](v15);
    v17 = MEMORY[0x111A95148](v16);
    v18 = MEMORY[0x111A951FC](v17);
    v19 = MEMORY[0x109E3C5A4](v18);
    v20 = MEMORY[0x109E0C63C](v19);
    v12 = MEMORY[0x109E0EBFC](v20);
  }
  v329 = v5;
  v21 = MEMORY[0x109E3BEE0](v12);
  v22 = MEMORY[0x109E13140](v21);
  v23 = MEMORY[0x109E198B8](v22);
  v24 = MEMORY[0x109E148EC](v23);
  v25 = MEMORY[0x111A95148](v24);
  MEMORY[0x111A951FC](v25);
  MEMORY[0x109E148E0]();
  v26 = MEMORY[0x109E0EBFC]();
  v27 = MEMORY[0x109E12D84](v26);
  v28 = MEMORY[0x109E3C594](v27);
  v29 = MEMORY[0x111A95148](v28);
  MEMORY[0x111A951FC](v29);
  v30 = MEMORY[0x109E3C584]();
  v31 = MEMORY[0x109E3C260](v30);
  v32 = MEMORY[0x109E0E964](v31);
  v33 = MEMORY[0x109E3C578](v32);
  v34 = MEMORY[0x109E14100](v33);
  v35 = MEMORY[0x111A95148](v34);
  MEMORY[0x111A951FC](v35);
  v36 = MEMORY[0x109E3C56C]();
  v37 = MEMORY[0x109E3C55C](v36);
  v38 = MEMORY[0x109E2233C](v37);
  v39 = MEMORY[0x111A95148](v38);
  MEMORY[0x111A951FC](v39);
  v40 = MEMORY[0x109E3C550]();
  v41 = MEMORY[0x109E3C484](v40);
  v42 = MEMORY[0x109E0E950](v41);
  v43 = MEMORY[0x109E0EFDC](v42);
  v44 = MEMORY[0x109E14100](v43);
  v45 = MEMORY[0x111A95148](v44);
  v46 = MEMORY[0x111A951FC](v45);
  v47 = MEMORY[0x109E3C540](v46);
  v48 = MEMORY[0x111A95148](v47);
  MEMORY[0x111A951FC](v48);
  v49 = MEMORY[0x109E14F20]();
  v50 = MEMORY[0x109E3C278](v49);
  v51 = MEMORY[0x109E0EFDC](v50);
  v52 = MEMORY[0x109E0E950](v51);
  v53 = MEMORY[0x109E14100](v52);
  v54 = MEMORY[0x111A95148](v53);
  MEMORY[0x111A951FC](v54);
  v55 = MEMORY[0x109E3B200]();
  v56 = MEMORY[0x111A95148](v55);
  MEMORY[0x111A951FC](v56);
  v57 = MEMORY[0x109E13110]();
  v58 = MEMORY[0x109E3C278](v57);
  v59 = MEMORY[0x109E0EFDC](v58);
  v60 = MEMORY[0x109E0E950](v59);
  v61 = MEMORY[0x109E14100](v60);
  v62 = MEMORY[0x111A95148](v61);
  MEMORY[0x111A951FC](v62);
  v63 = MEMORY[0x111A95148]();
  MEMORY[0x111A951FC](v63);
  v64 = MEMORY[0x109E13104]();
  v65 = MEMORY[0x109E3C278](v64);
  v66 = MEMORY[0x109E0EFDC](v65);
  v67 = MEMORY[0x109E0E950](v66);
  v68 = MEMORY[0x109E14100](v67);
  v69 = MEMORY[0x111A95148](v68);
  MEMORY[0x111A951FC](v69);
  v70 = MEMORY[0x111A95148]();
  MEMORY[0x111A951FC](v70);
  v71 = MEMORY[0x109E3C534]();
  v72 = MEMORY[0x109E3C278](v71);
  v73 = MEMORY[0x109E0EFDC](v72);
  v74 = MEMORY[0x109E0E950](v73);
  v75 = MEMORY[0x109E14100](v74);
  v76 = MEMORY[0x111A95148](v75);
  MEMORY[0x111A951FC](v76);
  v77 = MEMORY[0x111A95148]();
  MEMORY[0x111A951FC](v77);
  v78 = MEMORY[0x109E130F8]();
  v79 = MEMORY[0x109E3C278](v78);
  v80 = MEMORY[0x109E0EFDC](v79);
  v81 = MEMORY[0x109E0E950](v80);
  v82 = MEMORY[0x109E14100](v81);
  v83 = MEMORY[0x111A95148](v82);
  MEMORY[0x111A951FC](v83);
  v84 = MEMORY[0x109E3C528]();
  v85 = MEMORY[0x109E3C514](v84);
  v86 = MEMORY[0x111A95148](v85);
  MEMORY[0x111A951FC](v86);
  v87 = MEMORY[0x109E3C484]();
  v88 = MEMORY[0x109E0E950](v87);
  v89 = MEMORY[0x109E0EFDC](v88);
  v90 = MEMORY[0x109E14100](v89);
  v91 = MEMORY[0x111A95148](v90);
  MEMORY[0x111A951FC](v91);
  v92 = MEMORY[0x109E3C508]();
  v93 = MEMORY[0x109E3C4C8](v92);
  v94 = MEMORY[0x111A95148](v93);
  MEMORY[0x111A951FC](v94);
  v95 = MEMORY[0x109E14E40]();
  v96 = MEMORY[0x109E3C484](v95);
  v97 = MEMORY[0x109E0E950](v96);
  v98 = MEMORY[0x109E0EFDC](v97);
  v99 = MEMORY[0x109E14100](v98);
  v100 = MEMORY[0x111A95148](v99);
  MEMORY[0x111A951FC](v100);
  v101 = MEMORY[0x109E3C4FC]();
  v102 = MEMORY[0x111A95148](v101);
  MEMORY[0x111A951FC](v102);
  v103 = MEMORY[0x109E130CC]();
  v104 = MEMORY[0x109E3C278](v103);
  v105 = MEMORY[0x109E0EFDC](v104);
  v106 = MEMORY[0x109E0E950](v105);
  v107 = MEMORY[0x109E14100](v106);
  v108 = MEMORY[0x111A95148](v107);
  MEMORY[0x111A951FC](v108);
  v109 = MEMORY[0x109E36C20]();
  v110 = MEMORY[0x111A95148](v109);
  MEMORY[0x111A951FC](v110);
  v111 = MEMORY[0x109E14ED8]();
  v112 = MEMORY[0x109E3C278](v111);
  v113 = MEMORY[0x109E0EFDC](v112);
  v114 = MEMORY[0x109E0E950](v113);
  v115 = MEMORY[0x109E14100](v114);
  v116 = MEMORY[0x111A95148](v115);
  MEMORY[0x111A951FC](v116);
  v117 = MEMORY[0x109E36C04]();
  v118 = MEMORY[0x111A95148](v117);
  MEMORY[0x111A951FC](v118);
  v119 = MEMORY[0x109E3C4F0]();
  v120 = MEMORY[0x109E3C278](v119);
  v121 = MEMORY[0x109E0EFDC](v120);
  v122 = MEMORY[0x109E0E950](v121);
  v123 = MEMORY[0x109E14100](v122);
  v124 = MEMORY[0x111A95148](v123);
  MEMORY[0x111A951FC](v124);
  v125 = MEMORY[0x109E3C4E4]();
  v126 = MEMORY[0x111A95148](v125);
  MEMORY[0x111A951FC](v126);
  v127 = MEMORY[0x109E130C0]();
  v128 = MEMORY[0x109E3C278](v127);
  v129 = MEMORY[0x109E0EFDC](v128);
  v130 = MEMORY[0x109E0E950](v129);
  v131 = MEMORY[0x109E14100](v130);
  v132 = MEMORY[0x111A95148](v131);
  MEMORY[0x111A951FC](v132);
  v133 = MEMORY[0x109E3C4D8]();
  v134 = MEMORY[0x109E3C4C8](v133);
  v135 = MEMORY[0x111A95148](v134);
  MEMORY[0x111A951FC](v135);
  v136 = MEMORY[0x109E3C4BC]();
  v137 = MEMORY[0x109E3C4AC](v136);
  v138 = MEMORY[0x109E11424](v137);
  v139 = MEMORY[0x109E0EFDC](v138);
  v140 = MEMORY[0x109E12D14](v139);
  v141 = MEMORY[0x109E3C4A0](v140);
  v142 = MEMORY[0x109E198B8](v141);
  v143 = MEMORY[0x109E14100](v142);
  v144 = MEMORY[0x111A95148](v143);
  MEMORY[0x111A951FC](v144);
  v145 = MEMORY[0x111A95148]();
  MEMORY[0x111A951FC](v145);
  v146 = MEMORY[0x109E1309C]();
  v147 = MEMORY[0x109E3C278](v146);
  v148 = MEMORY[0x109E0EFDC](v147);
  v149 = MEMORY[0x109E11424](v148);
  v150 = MEMORY[0x109E14100](v149);
  v151 = MEMORY[0x111A95148](v150);
  v152 = MEMORY[0x111A951FC](v151);
  v153 = MEMORY[0x109E3C494](v152);
  v154 = MEMORY[0x111A95148](v153);
  MEMORY[0x111A951FC](v154);
  v155 = MEMORY[0x109E13090]();
  v156 = MEMORY[0x109E3C484](v155);
  v157 = MEMORY[0x109E0E950](v156);
  v158 = MEMORY[0x109E11424](v157);
  v330 = v1;
  v159 = MEMORY[0x109E14100](v158);
  v160 = MEMORY[0x111A95148](v159);
  MEMORY[0x111A951FC](v160);
  v161 = MEMORY[0x109E3C478]();
  v162 = MEMORY[0x111A95148](v161);
  v163 = MEMORY[0x109E3C468](v162);
  v164 = MEMORY[0x111A95148](v163);
  MEMORY[0x111A951FC](v164);
  v165 = MEMORY[0x109E3C388]();
  v166 = MEMORY[0x109E0EBFC](v165);
  MEMORY[0x109E0E964](v166);
  v167 = MEMORY[0x109E3C45C](MEMORY[0x11C5A3A20]);
  v168 = MEMORY[0x111A95148](v167);
  v169 = MEMORY[0x111A951FC](v168);
  v170 = MEMORY[0x109E3C448](v169);
  v171 = MEMORY[0x109E3C43C](v170);
  v172 = MEMORY[0x109E0EBFC](v171);
  v173 = MEMORY[0x109E3C42C](v172);
  MEMORY[0x109E3C420](v173, v8);
  v174 = MEMORY[0x109E3C414](MEMORY[0x11C5A3A20]);
  v175 = MEMORY[0x111A95148](v174);
  MEMORY[0x111A951FC](v175);
  v176 = MEMORY[0x109E3C404]();
  MEMORY[0x109E0EBFC](v176);
  v177 = MEMORY[0x109E3C3F8](MEMORY[0x11C5A3A20]);
  v178 = MEMORY[0x111A95148](v177);
  v179 = MEMORY[0x111A951FC](v178);
  v180 = MEMORY[0x109E3C3E4](v179);
  v181 = MEMORY[0x109E0EBFC](v180);
  v182 = MEMORY[0x109E18FB8](v181);
  v184 = *(_QWORD *)(v183 + 4016);
  v185 = MEMORY[0x109E3C3D8](v182);
  v186 = MEMORY[0x111A95148](v185, v184);
  MEMORY[0x111A951FC](v186);
  v187 = MEMORY[0x109E3C3CC]();
  v188 = MEMORY[0x109E3C388](v187);
  MEMORY[0x109E0EBFC](v188);
  v189 = MEMORY[0x109E3C3C0](MEMORY[0x11C5A3A20]);
  v190 = MEMORY[0x111A95148](v189);
  MEMORY[0x111A951FC](v190);
  v191 = MEMORY[0x109E3C3B4]();
  v192 = MEMORY[0x109E3C388](v191);
  MEMORY[0x109E0EBFC](v192);
  v193 = MEMORY[0x111A95148](MEMORY[0x11C5A3A20], MEMORY[0x11C160668]);
  v194 = MEMORY[0x111A951FC](v193);
  if ( MEMORY[0x109E3C3A8](v194) )
  {
    v195 = MEMORY[0x109E3C398]();
    v196 = MEMORY[0x111A95148](v195);
    MEMORY[0x111A951FC](v196);
    v197 = MEMORY[0x109E3C340]();
    v198 = MEMORY[0x109E3C388](v197);
    v199 = MEMORY[0x109E0EBFC](v198);
    v200 = MEMORY[0x109E3C37C](v199);
    for ( i = 1; ; ++i )
    {
      v202 = MEMORY[0x109E3C370](v200);
      if ( i >= v202 )
        break;
      v203 = MEMORY[0x109E3C360]();
      v204 = MEMORY[0x111A95148](v203);
      v205 = MEMORY[0x111A951FC](v204);
      v206 = MEMORY[0x109E0EB50](v205);
      v207 = MEMORY[0x109E3A914](v206);
      v208 = MEMORY[0x111A95148](v207);
      MEMORY[0x111A951FC](v208);
      v209 = MEMORY[0x109E3C34C]();
      v210 = MEMORY[0x109E0DD6C](v209);
      v200 = MEMORY[0x109E0C5BC](v210);
    }
  }
  else
  {
    v211 = MEMORY[0x109E37648]();
    v212 = MEMORY[0x109E3C340](v211);
    v202 = MEMORY[0x109E198B8](v212);
  }
  v213 = MEMORY[0x109E141C8](v202);
  v214 = MEMORY[0x111A95148](v213);
  v215 = MEMORY[0x111A951FC](v214);
  v216 = MEMORY[0x109E3C330](v215);
  v217 = MEMORY[0x111A95148](v216);
  v218 = MEMORY[0x111A951FC](v217);
  v219 = MEMORY[0x109E3C320](v218);
  v220 = MEMORY[0x109E3C298](v219);
  v221 = MEMORY[0x109E0C5BC](v220);
  v222 = MEMORY[0x109E0DD6C](v221);
  v223 = MEMORY[0x109E141C8](v222);
  v224 = MEMORY[0x111A95148](v223);
  v225 = MEMORY[0x111A951FC](v224);
  v226 = MEMORY[0x109E395DC](v225);
  v227 = MEMORY[0x111A95148](v226);
  v228 = MEMORY[0x111A951FC](v227);
  v229 = MEMORY[0x109E3C310](v228);
  v230 = MEMORY[0x109E3C298](v229);
  v231 = MEMORY[0x109E0C5BC](v230);
  v232 = MEMORY[0x109E0DD6C](v231);
  v233 = MEMORY[0x109E141C8](v232);
  v234 = MEMORY[0x111A95148](v233);
  MEMORY[0x111A951FC](v234);
  v235 = MEMORY[0x109E3C304]();
  v236 = MEMORY[0x111A95148](v235);
  v237 = MEMORY[0x111A951FC](v236);
  v238 = MEMORY[0x109E3C2F4](v237);
  v239 = MEMORY[0x109E3C298](v238);
  v240 = MEMORY[0x109E0C5BC](v239);
  v241 = MEMORY[0x109E0DD6C](v240);
  v242 = MEMORY[0x109E141C8](v241);
  v243 = MEMORY[0x111A95148](v242);
  MEMORY[0x111A951FC](v243);
  v244 = MEMORY[0x109E330CC]();
  v245 = MEMORY[0x111A95148](v244);
  MEMORY[0x111A951FC](v245);
  v246 = MEMORY[0x109E13060]();
  v247 = MEMORY[0x109E3C298](v246);
  v248 = MEMORY[0x109E0C5BC](v247);
  v249 = MEMORY[0x109E0DD6C](v248);
  v250 = MEMORY[0x109E141C8](v249);
  v251 = MEMORY[0x111A95148](v250);
  v252 = MEMORY[0x111A951FC](v251);
  v253 = MEMORY[0x109E3C2E4](v252);
  v254 = MEMORY[0x111A95148](v253);
  v255 = MEMORY[0x111A951FC](v254);
  v256 = MEMORY[0x109E3C2D4](v255);
  v257 = MEMORY[0x109E3C298](v256);
  v258 = MEMORY[0x109E0C5BC](v257);
  v259 = MEMORY[0x109E0DD6C](v258);
  v260 = MEMORY[0x109E141C8](v259);
  v261 = MEMORY[0x111A95148](v260);
  v262 = MEMORY[0x111A951FC](v261);
  v263 = MEMORY[0x109E3C2C4](v262);
  v264 = MEMORY[0x111A95148](v263);
  v265 = MEMORY[0x111A951FC](v264);
  v266 = MEMORY[0x109E13048]();
  v267 = MEMORY[0x109E3C298](v266);
  v268 = MEMORY[0x109E0C5BC](v267);
  v269 = MEMORY[0x109E0DD6C](v268);
  v270 = MEMORY[0x109E141C8](v269);
  v271 = MEMORY[0x111A95148](v270);
  MEMORY[0x111A951FC](v271);
  v272 = MEMORY[0x111A95148]();
  v273 = MEMORY[0x111A951FC](v272);
  v274 = MEMORY[0x109E2F580](v273);
  v275 = MEMORY[0x109E0DD6C](v274);
  if ( v265 )
  {
    v276 = MEMORY[0x109E141C8](v275);
    v277 = MEMORY[0x111A95148](v276);
    v278 = MEMORY[0x111A951FC](v277);
    v279 = MEMORY[0x109E32694](v278);
    v280 = MEMORY[0x111A95148](v279);
    v265 = MEMORY[0x111A951FC](v280);
    v281 = MEMORY[0x109E1303C]();
    v282 = MEMORY[0x109E3C298](v281);
    v283 = MEMORY[0x109E0C5BC](v282);
    v275 = MEMORY[0x109E0DD6C](v283);
  }
  v284 = MEMORY[0x109E141C8](v275);
  v285 = MEMORY[0x111A95148](v284);
  MEMORY[0x111A951FC](v285);
  v286 = MEMORY[0x111A95148]();
  v287 = MEMORY[0x111A951FC](v286);
  v288 = MEMORY[0x109E2F580](v287);
  v289 = MEMORY[0x109E0DD6C](v288);
  if ( v265 )
  {
    v290 = MEMORY[0x109E141C8](v289);
    v291 = MEMORY[0x111A95148](v290);
    v292 = MEMORY[0x111A951FC](v291);
    v293 = MEMORY[0x109E32694](v292);
    v294 = MEMORY[0x111A95148](v293);
    MEMORY[0x111A951FC](v294);
    v295 = MEMORY[0x109E13020]();
    v296 = MEMORY[0x109E3C298](v295);
    v297 = MEMORY[0x109E0C5BC](v296);
    v289 = MEMORY[0x109E0DD6C](v297);
  }
  v298 = MEMORY[0x109E3C2B4](v289);
  v299 = MEMORY[0x109E3C2A8](v298);
  v300 = MEMORY[0x111A95148](v299);
  v301 = MEMORY[0x111A951FC](v300);
  v302 = MEMORY[0x109E3A81C]();
  v303 = MEMORY[0x111A95148](v302);
  v304 = MEMORY[0x111A951FC](v303);
  MEMORY[0x109E36B10]();
  v305 = MEMORY[0x111A95148](v301);
  v306 = MEMORY[0x111A951FC](v305);
  v307 = MEMORY[0x111A95148](v301, MEMORY[0x11C14FB80]);
  v308 = MEMORY[0x111A951FC](v307);
  if ( v304 )
    MEMORY[0x109E3C298]();
  if ( v306 )
  {
    v309 = MEMORY[0x109E14E8C]();
    MEMORY[0x109E3C288](v309);
  }
  if ( v308 )
    MEMORY[0x109E3C278]();
  v310 = MEMORY[0x109E32418](*(_QWORD *)(v329 + 2584));
  if ( (_DWORD)v310 )
  {
    v311 = MEMORY[0x111A95148](*(_QWORD *)(v329 + 2584), v330);
    MEMORY[0x111A951FC](v311);
    v312 = MEMORY[0x109E3C26C]();
    v313 = MEMORY[0x111A95148](v312);
    MEMORY[0x111A951FC](v313);
    v314 = MEMORY[0x109E3C260](v4);
    v315 = MEMORY[0x109E0E964](v314);
    v316 = MEMORY[0x109E0EBFC](v315);
    v317 = MEMORY[0x109E2342C](v316);
    v318 = MEMORY[0x109E3C254](v317);
    v310 = MEMORY[0x109E198B8](v318);
  }
  v319 = MEMORY[0x109E24C70](v310);
  v320 = MEMORY[0x109E38ACC](v319);
  v321 = MEMORY[0x109E0DBBC](v320);
  v322 = MEMORY[0x109E0C5BC](v321);
  v323 = MEMORY[0x109E0DD6C](v322);
  v324 = MEMORY[0x109E0E950](v323);
  v325 = MEMORY[0x109E16E1C](v324);
  v326 = MEMORY[0x109E16E14](v325);
  v327 = MEMORY[0x109E0DEDC](v326);
  v328 = MEMORY[0x109E0C58C](v327);
  MEMORY[0x109E3C248](v328);
  JUMPOUT(0x111A95010LL);
}
