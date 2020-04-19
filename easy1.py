
#6bit sbox.
s = [16, 42, 28, 3, 26, 0, 31, 46, 27, 14, 49, 62, 37, 56, 23, 6, 40, 48, 53, 8, 20, 25, 33, 1, 2, 63, 15, 34, 55, 21, 39, 57, 54, 45, 47, 13, 7, 44, 61, 9, 60, 32, 22, 29, 52, 19, 12, 50, 5, 51, 11, 18, 59, 41, 36, 30, 17, 38, 10, 4, 58, 43, 35, 24]

s_inv = {16:0, 42:1, 28:2, 3:3, 26:4, 0:5, 31:6, 46:7, 27:8, 14:9, 49:10, 62:11, 37:12, 56:13, 23:14, 6:15, 40:16, 48:17, 53:18, 8:19, 20:20, 25:21, 33:22, 1:23, 2:24, 63:25, 15:26, 34:27, 55:28, 21:29, 39:30, 57:31, 54:32, 45:33, 47:34, 13:35, 7:36, 44:37, 61:38, 9:39, 60:40, 32:41, 22:42, 29:43, 52:44, 19:45, 12:46, 50:47, 5:48, 51:49, 11:50, 18:51, 59:52, 41:53, 36:54, 30:55, 17:56, 38:57, 10:58, 4:59, 58:60, 43:61, 35:62, 24:63}

p = [24, 5, 15, 23, 14, 32, 19, 18, 26, 17, 6, 12, 34, 9, 8, 20, 28, 0, 2, 21, 29, 11, 33, 22, 30, 31, 1, 25, 3, 35, 16, 13, 27, 7, 10, 4]

def sbox(x):
    return s[x]

def sbox_inv(x):
    return s_inv[x]

def pbox(x):
    # if the texts are more than 32 bits,
    # then we have to use longs
    y = 0

    # for each bit to be shuffled
    for i in range(len(p)):

        # if the original bit position
        # is a 1, then make the result
        # bit position have a 1
        if (x & (1 << i)) != 0:
            y = y ^ (1 << p[i])
   
    return y
 
def demux(x):
    y = []
    for i in range(6):
        y.append((x >> (i * 6)) & 0b111111)

    return y

def mux(x):
    y = 0
    for i in range(6):
        y = y ^ (x[i] << (i * 6))

    return y

def mix(p, k):
    v = []
    key = demux(k)
    for i in range(6):
        v.append(p[i] ^ key[i])

    return v
 
def round(p, k, last=False):
    u = []

    # Calculate the S-boxes
    for x in demux(p):
        u.append(sbox(x))

    if last is False:
        # Run through the P-box
        v = demux(pbox(mux(u)))
    else:
        # Skip last P-box
        v = u

    # XOR in the key
    w = mix(v, k)

    # Glue back together, return
    return mux(w)
 
def encrypt(key, p, rounds):
    x = p
    for i in range(rounds):
        x = round(x, key, last=(i==rounds-1))

    return x
 
def apbox(x):
    y = 0
    for i in range(len(p)):
        if (x & (1 << i)) != 0:
            pval = p.index(i)
            y = y ^ (1 << pval)
    return y
 
def asbox(x):
    return s.index(x)
 
def unround(c, k, first=False):
    x = demux(c)

    u = mix(x, k)

    if first is False:
        v = demux(apbox(mux(u)))
    else:
        v = u

    w = []
    for s in v:
        w.append(asbox(s))

    return mux(w)
 
def decrypt(key, c, rounds):
    x = c
    for i in range(rounds):
        x = unround(x, key, first=(i==0))

    return x
