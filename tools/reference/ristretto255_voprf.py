#!/usr/bin/env python3
"""
Independent reference implementation of ristretto255 (RFC 9496) and RFC 9497 VOPRF(ristretto255, SHA-512).

PURPOSE: an independent cross-check for reviewers of packages/protocol/src/voprf. NOT constant-time, NOT for production use.
Written separately from the TypeScript implementation; both follow the RFC text, so a shared misreading is possible -
the official RFC vectors (npm run test:vectors) remain the arbiter.

    python3 tools/reference/ristretto255_voprf.py        # runs the self-test (known-answer values from RFC 9496 / RFC 9497 A.1.1)
"""
import hashlib
p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
SQRT_M1 = pow(2, (p - 1) // 4, p)
L = 2**252 + 27742317777372353535851937790883648493
def inv(x): return pow(x, -1, p)
def is_neg(x): return x % 2 == 1
def cabs(x): x %= p; return (-x) % p if is_neg(x) else x
def sqrt_ratio_m1(u, v):
    v3 = v*v % p * v % p; v7 = v3*v3 % p * v % p
    r = u*v3 % p * pow(u*v7 % p, (p-5)//8, p) % p
    check = v*r % p * r % p
    correct = check == u % p; flipped = check == (-u) % p; flipped_i = check == (-u*SQRT_M1) % p
    if flipped or flipped_i: r = SQRT_M1*r % p
    r = cabs(r)
    return (correct or flipped), r
def _sqrt(x):
    ok, r = sqrt_ratio_m1(x, 1); assert ok; return r
INVSQRT_A_MINUS_D = inv(_sqrt((-1 - d) % p))
SQRT_AD_MINUS_ONE = (p - _sqrt((-d - 1) % p)) % p  # RFC 9496 constant is the NEGATIVE root
ONE_MINUS_D_SQ = (1 - d*d) % p
D_MINUS_ONE_SQ = (d-1)**2 % p
def add(P, Q):
    X1,Y1,Z1,T1 = P; X2,Y2,Z2,T2 = Q
    A=(Y1-X1)*(Y2-X2)%p; B=(Y1+X1)*(Y2+X2)%p; C=T1*2*d%p*T2%p; D=Z1*2*Z2%p
    E=B-A; F=D-C; G=D+C; H=B+A
    return (E*F%p, G*H%p, F*G%p, E*H%p)
ID = (0,1,1,0)
def mul(P, k):
    k %= L; R = ID
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R
def encode(P):
    x0,y0,z0,t0 = P
    u1=(z0+y0)*(z0-y0)%p; u2=x0*y0%p
    _, invsqrt = sqrt_ratio_m1(1, u1*u2%p*u2%p)
    den1=invsqrt*u1%p; den2=invsqrt*u2%p; z_inv=den1*den2%p*t0%p
    ix0=x0*SQRT_M1%p; iy0=y0*SQRT_M1%p; ench=den1*INVSQRT_A_MINUS_D%p
    if is_neg(t0*z_inv%p): x,y,den_inv = iy0,ix0,ench
    else: x,y,den_inv = x0,y0,den2
    if is_neg(x*z_inv%p): y=(-y)%p
    s = cabs((z0-y)*den_inv%p)
    return s.to_bytes(32,'little')
def decode(b):
    s = int.from_bytes(b,'little')
    if s >= p or is_neg(s): raise ValueError('bad')
    ss=s*s%p; u1=(1-ss)%p; u2=(1+ss)%p; u2s=u2*u2%p
    v=(-(d*u1%p*u1) - u2s)%p
    ok,I = sqrt_ratio_m1(1, v*u2s%p)
    Dx=I*u2%p; Dy=I*Dx%p*v%p
    x=cabs(2*s*Dx%p); y=u1*Dy%p; t=x*y%p
    if not ok or is_neg(t) or y==0: raise ValueError('bad')
    return (x,y,1,t)
def elligator(t):
    r=SQRT_M1*t%p*t%p; u=(r+1)*ONE_MINUS_D_SQ%p; v=((-1-r*d)%p)*((r+d)%p)%p
    ws,s = sqrt_ratio_m1(u,v); sp=(-cabs(s*t%p))%p
    s = s if ws else sp; c = (-1)%p if ws else r
    N=(c*((r-1)%p)%p*D_MINUS_ONE_SQ - v)%p
    w0=2*s*v%p; w1=N*SQRT_AD_MINUS_ONE%p; w2=(1-s*s)%p; w3=(1+s*s)%p
    return (w0*w3%p, w2*w1%p, w1*w3%p, w0*w2%p)
def from_uniform(b64):
    r0=int.from_bytes(b64[:32],'little') & ((1<<255)-1); r1=int.from_bytes(b64[32:],'little') & ((1<<255)-1)
    return add(elligator(r0%p), elligator(r1%p))
# base point
By = 4*inv(5)%p
def _recover_x(y):
    xx=(y*y-1)*inv(d*y*y+1)%p; ok,x=sqrt_ratio_m1(xx,1); assert ok; return x
Bx=_recover_x(By)
if Bx%2: Bx=p-Bx
G=(Bx,By,1,Bx*By%p)
def expand_xmd(msg,dst,n):
    b,r=64,128; ell=-(-n//b); dp=dst+bytes([len(dst)])
    b0=hashlib.sha512(bytes(r)+msg+n.to_bytes(2,'big')+b'\x00'+dp).digest()
    bi=hashlib.sha512(b0+b'\x01'+dp).digest(); out=bi
    for i in range(2,ell+1):
        bi=hashlib.sha512(bytes(a^c for a,c in zip(b0,bi))+bytes([i])+dp).digest(); out+=bi
    return out[:n]
def ctx(mode): return b'OPRFV1-'+bytes([mode])+b'-ristretto255-SHA512'
def hash_to_group(m,mode,dst=None): return from_uniform(expand_xmd(m,(dst if dst is not None else b'HashToGroup-'+ctx(mode)),64))
def hash_to_scalar(m,mode,dst=None):
    return int.from_bytes(expand_xmd(m,(dst if dst is not None else b'HashToScalar-'+ctx(mode)),64),'little')%L
def i2(n,l): return n.to_bytes(l,'big')
def sser(s): return (s%L).to_bytes(32,'little')
def derive_key_pair(seed,info,mode):
    di=seed+i2(len(info),2)+info; c=0
    while True:
        assert c<256
        sk=hash_to_scalar(di+bytes([c]),mode,b'DeriveKeyPair'+ctx(mode)); 
        if sk!=0: return sk, encode(mul(G,sk))
        c+=1
def composites(k,B,Cs,Ds,mode):
    Bm=encode(B); seed=hashlib.sha512(i2(len(Bm),2)+Bm+i2(len(b'Seed-'+ctx(mode)),2)+b'Seed-'+ctx(mode)).digest()
    M=ID; Z=ID
    for i,(Ci,Di) in enumerate(zip(Cs,Ds)):
        ci,di_=encode(Ci),encode(Di)
        h=i2(len(seed),2)+seed+i2(i,2)+i2(len(ci),2)+ci+i2(len(di_),2)+di_+b'Composite'
        s=hash_to_scalar(h,mode); M=add(mul(Ci,s),M); Z=add(mul(Di,s),Z)
    if k is not None: Z=mul(M,k)
    return M,Z
def gen_proof(k,A,B,Cs,Ds,r,mode):
    M,Z=composites(k,B,Cs,Ds,mode); t2=mul(A,r); t3=mul(M,r)
    Bm,a0,a1,a2,a3=encode(B),encode(M),encode(Z),encode(t2),encode(t3)
    tr=i2(len(Bm),2)+Bm+i2(len(a0),2)+a0+i2(len(a1),2)+a1+i2(len(a2),2)+a2+i2(len(a3),2)+a3+b'Challenge'
    c=hash_to_scalar(tr,mode); s=(r-c*k)%L
    return sser(c)+sser(s)
def verify_proof(A,B,Cs,Ds,proof,mode):
    M,Z=composites(None,B,Cs,Ds,mode)
    c=int.from_bytes(proof[:32],'little'); s=int.from_bytes(proof[32:],'little')
    t2=add(mul(A,s),mul(B,c)); t3=add(mul(M,s),mul(Z,c))
    Bm,a0,a1,a2,a3=encode(B),encode(M),encode(Z),encode(t2),encode(t3)
    tr=i2(len(Bm),2)+Bm+i2(len(a0),2)+a0+i2(len(a1),2)+a1+i2(len(a2),2)+a2+i2(len(a3),2)+a3+b'Challenge'
    return hash_to_scalar(tr,mode)==c
def finalize_hash(inp,N): 
    return hashlib.sha512(i2(len(inp),2)+inp+i2(32,2)+N+b'Finalize').digest()


def _selftest():
    import hashlib
    assert encode(G).hex() == "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"          # RFC 9496 generator
    assert encode(mul(G, 2)).hex() == "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"   # RFC 9496 2*G
    h = hashlib.sha512(b"Ristretto is traditionally a short shot of espresso coffee").digest()
    assert encode(from_uniform(h)).hex() == "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"  # RFC 9496 A.3
    seed, info = bytes([0xa3]) * 32, b"test key"
    assert sser(derive_key_pair(seed, info, 0)[0]).hex() == "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
    sk1, pk1 = derive_key_pair(seed, info, 1)
    assert sser(sk1).hex() == "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"
    assert pk1.hex() == "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"
    sk0, _ = derive_key_pair(seed, info, 0)
    blind = int.from_bytes(bytes.fromhex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"), "little")
    A = mul(hash_to_group(b"\x00", 0), blind); E = mul(A, sk0)
    assert encode(A).hex() == "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"          # RFC 9497 A.1.1 vector 1
    assert encode(E).hex() == "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"
    out = finalize_hash(b"\x00", encode(mul(E, pow(blind, -1, L)))).hex()
    assert out.startswith("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f")
    # VOPRF proof round trip (mode 1) with the proof randomness used in the TypeScript cross-check
    A1 = mul(hash_to_group(b"\x00", 1), blind); B1 = mul(A1, sk1)
    r = int.from_bytes(bytes.fromhex("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"), "little")
    proof = gen_proof(sk1, G, decode(pk1), [A1], [B1], r, 1)
    assert proof.hex() == "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"
    assert verify_proof(G, decode(pk1), [A1], [B1], proof, 1)
    print("self-test OK")


if __name__ == "__main__":
    _selftest()
