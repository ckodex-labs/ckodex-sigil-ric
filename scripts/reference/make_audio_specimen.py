# Builds the audio specimen: audible benign speech + hidden speech moved to 32-39.5 kHz in a 96 kHz WAV.
import numpy as np, soundfile as sf, json, hashlib
from scipy.signal import resample_poly, hilbert, butter, sosfiltfilt
SR=96000
b,sb=sf.read("benign.wav",dtype="float64"); h,sh=sf.read("hidden.wav",dtype="float64")
up=lambda x,s: resample_poly(x,SR,s)   # 22050 -> 96000 (polyphase, anti-imaged)
b=up(b,sb); h=up(h,sh)
h=sosfiltfilt(butter(10,7500,fs=SR,output="sos"),h)          # band-limit hidden speech below 7.5 kHz
t=np.arange(len(h))/SR
F=32000.0                                                     # 2 x 16 kHz: folds back to baseband under x[::6]
h_up=np.real(hilbert(h)*np.exp(2j*np.pi*F*t))                 # single-sideband shift -> 32.0-39.5 kHz
gap=int(0.6*SR); L=gap+len(b)+gap+len(h_up)+gap
x=np.zeros(L); x[gap:gap+len(b)]+=b
o=gap+len(b)+gap; x[o:o+len(h_up)]+=h_up*1.0
x=x/np.max(np.abs(x))*0.89
sf.write("attack_96k.wav",x,SR,subtype="PCM_16")
# the two model-side views
sf.write("naive_16k.wav",x[::6],16000,subtype="PCM_16")      # decimate by 6, no low-pass
meta={"sr":SR,"shift_hz":F,"hidden_band_hz":[F,F+7500],"benign_s":[gap/SR,(gap+len(b))/SR],"hidden_s":[o/SR,(o+len(h_up))/SR],"dur_s":L/SR,
 "sha384":hashlib.sha384(open("attack_96k.wav","rb").read()).hexdigest()}
json.dump(meta,open("audio_meta.json","w"),indent=1); print(meta)
