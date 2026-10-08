import curl_cffi
import ua_generator
from ua_generator.options import Options
from ua_generator.data.version import VersionRange
import imgsolver
import hashlib
import time
import uuid
import math

def transactionSignature(_0x4990fd, _0x4cd178):
  return "TH[" + hashlib.md5((_0x4cd178 + _0x4990fd).encode()).hexdigest() + "]"

def int32(n):
  n = n & 0xFFFFFFFF
  if n >= 0x80000000:
    n -= 0x100000000
  return n

_URLSAFE_B64_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
_URLSAFE_B64_CHAR2INT = {c: i for i, c in enumerate(_URLSAFE_B64_CHARS)}

class FoldChlg:
  @staticmethod
  def URLSafeBase64CharToInt(_0x5db43a):
    return _URLSAFE_B64_CHAR2INT.get(_0x5db43a[0], -1)

  @staticmethod
  def URLSafeBase64IntToChar(_0x26f8c7):
    return _URLSAFE_B64_CHARS[_0x26f8c7 % 0x40]

  @staticmethod
  def URLSafeBase4096IntToChar(_0x101738):
    return "" + FoldChlg.URLSafeBase64IntToChar(_0x101738 >> 0x6) + FoldChlg.URLSafeBase64IntToChar(_0x101738 & 0x3f)

  @staticmethod
  def URLSafeBase64Str2IntArray(_0x42402c):
    _0x379e1d = []
    for _0x411f36 in range(len(_0x42402c)):
      _0x379e1d.append(FoldChlg.URLSafeBase64CharToInt(_0x42402c[_0x411f36]))
    return _0x379e1d

  @staticmethod
  def hashIntAry(_0x2c7601):
    _0x4bb62d = 0x0
    for _0x504548 in range(len(_0x2c7601)):
      _0x4bb62d = int32(_0x4bb62d << 0x5) - _0x4bb62d + _0x2c7601[_0x504548]
      _0x4bb62d = int32(_0x4bb62d & _0x4bb62d)
    if _0x4bb62d < 0x0:
      _0x4bb62d *= -0x1
    return _0x4bb62d

  @staticmethod
  def solve(_0x158a06, _0x4c6381, _0x43e330):
    _0x311562 = []
    _0x3d9dd9 = FoldChlg.URLSafeBase64Str2IntArray(_0x158a06)
    for _0x26938f in range(_0x4c6381):
      _0x3d9dd9 = FoldChlg.foldBase64IntArray(_0x3d9dd9, 0x1f)
      _0x23dab8 = FoldChlg.hashIntAry(FoldChlg.foldBase64IntArray(_0x3d9dd9, _0x43e330))
      _0x311562.append(FoldChlg.URLSafeBase4096IntToChar(_0x23dab8 % 0x1000))
    return "".join(_0x311562)

  @staticmethod
  def foldBase64IntArray(a1, foldCount):
    a2 = [a for a in a1][::-1]
    a3 = [a for a in a1]
    offset = x = y = z = i = 0
    for i in range(foldCount):
      offset += 1
      for x in range(len(a1)):
        a3[x] = (math.floor((a3[x] + a2[(x + offset) % len(a2)]) * 73 / 8) + y + z) % 64
        z = math.floor(y / 2)
        y = math.floor(a3[x] / 2)
    return a3


def solve(sitekey, url, proxy=None, log=False):
  chrome_v = 131
  ua_options = Options()
  ua_options.version_ranges = {
    'chrome': VersionRange(chrome_v, chrome_v)
  }
  s = curl_cffi.Session(impersonate="chrome131")
  ua = ua_generator.generate(browser='chrome', platform="ios", options=ua_options)
  s.headers = {"User-Agent": ua.text, "Referer": "https://service.mtcaptcha.com/"}
  if proxy != None:
    s.proxies.update({"https": proxy})
  domain = url.split("/")[2]
  ss = f"S1{str(uuid.uuid4())}"

  try:
    s.get("https://service.mtcaptcha.com/mtcv1/client.iframe.html", params={
      "action": "",
      "autoFadeOuterText": "false",
      "challengeType": "standard",
      "custom": "false",
      "enableMouseFlow": "false",
      "host": f"https://{domain}",
      "hostname": domain,
      "iframeId": "mtcaptcha-iframe-1",
      "lang": "en",
      "lowFrictionInvisible": "",
      "serviceDomain": "service.mtcaptcha.com",
      "sitekey": sitekey,
      "textLength": "0",
      "theme": "basic",
      "v": "2024-11-14.21.53.06",
      "widgetInstance": "mtcaptcha",
      "widgetSize": "standard"
    })
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to load iframe | {e}")
    return "Failed"

  try:
    r = s.get("https://service.mtcaptcha.com/mtcv1/api/getchallenge.json", params={
      "sk": sitekey,
      "bd": domain,
      "rt": str(int(time.time() * 1000)),
      "act": "$",
      "lf": "1",
      "tl": "$",
      "lg": "en",
      "tp": "s",
      "ss": ss,
      "tsh": transactionSignature(sitekey, "mtcap@mtcaptcha.com")
    })
    ct = None
    foldChlg = None
    if "result" in r.json():
      if "challenge" in r.json()["result"]:
        ct = r.json()["result"]["challenge"]["ct"]
        foldChlg = r.json()["result"]["challenge"]["foldChlg"]
        if log == True:
          print(f"(MTCaptcha Solver log) Got Challenge -> {ct}")
          if foldChlg["fdepth"] > 2000:
            print(f"(MTCaptcha Solver log) huge foldChlg, it means your proxy is flagged and it causes solving to take a long time -> {foldChlg}")
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to get challenge | {e}")
    return "Failed"

  if ct == None or foldChlg == None:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to get challenge | {r.text}")
    return "Failed"

  if foldChlg["preRes"] == True:
    foldChlg["fa"] = FoldChlg.solve(foldChlg["fseed"], foldChlg["fslots"], foldChlg["fdepth"])

  try:
    r = s.get("https://service.mtcaptcha.com/mtcv1/api/getimage.json", params={
      "sk": sitekey,
      "ct": ct,
      "fa": foldChlg["fa"] if "fa" in foldChlg else "$",
      "ss": ss
    })
    imgbase64 = None
    if "result" in r.json():
      if "img" in r.json()["result"]:
        imgbase64 = r.json()["result"]["img"]["image64"]
        if log == True:
          print(f"(MTCaptcha Solver log) Got Image -> {imgbase64[:40]}...")
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to get image | {e}")
    return "Failed"

  if imgbase64 == None:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to get image | {r.text}")
    return "Failed"

  try:
    s.get("https://service.mtcaptcha.com/mtcv1/api/getaudio.json", params={
      "sk": sitekey,
      "ct": ct,
      "fa": foldChlg["fa"] if "fa" in foldChlg else "$",
      "ss": ss
    })
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to get audio | {e}")
    return "Failed"

  try:
    cap_text = imgsolver.solve(imgbase64)
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to solve image | {e}")
    return "Failed"

  if log == True:
    print(f"(MTCaptcha Solver log) Image solved -> {cap_text}")

  try:
    r = s.get("https://service.mtcaptcha.com/mtcv1/api/solvechallenge.json", params={
      "sk": sitekey,
      "ct": ct,
      "st": cap_text,
      "lf": "1",
      "bd": domain,
      "rt": str(int(time.time() * 1000)),
      "tsh": transactionSignature(sitekey, "mtcap@mtcaptcha.com"),
      "fa": foldChlg["fa"] if "fa" in foldChlg else FoldChlg.solve(foldChlg["fseed"], foldChlg["fslots"], foldChlg["fdepth"]),
      "qh": "$",
      "act": "$",
      "ss": ss,
      "tl": "$",
      "lg": "en",
      "tp": "s",
      "kt": "AAA",
      "fs": foldChlg["fseed"]
    })
    token = None
    if "result" in r.json():
      if "verifyResult" in r.json()["result"]:
        if "verifiedToken" in r.json()["result"]["verifyResult"]:
          if "vt" in r.json()["result"]["verifyResult"]["verifiedToken"]:
            token = r.json()["result"]["verifyResult"]["verifiedToken"]["vt"]
            if log == True:
              print(f"(MTCaptcha Solver log) MTCaptcha Solved -> {token[:60]}...")
            return token
  except Exception as e:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to submit answer | {e}")
    return "Failed"

  if token == None:
    if log == True:
      print(f"(MTCaptcha Solver log) Failed to submit answer | {r.text}")
    return "Failed"
