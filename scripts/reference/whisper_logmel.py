# Spectrograms of the three audio representations plus Whisper's 80-bin log-mel input (same maths as whisper/audio.py).
import numpy as np, soundfile as sf, json
from PIL import Image
from scipy.signal import stft
def alpha_png(M, path, gamma=1.0):
    M=np.clip(M,0,1)**gamma; a=(M*255).astype(np.uint8)
    rgba=np.zeros(M.shape+(4,),np.uint8); rgba[...,0]=33; rgba[...,1]=27; rgba[...,2]=20; rgba[...,3]=a[::-1]      # low frequency at the bottom
    Image.fromarray(rgba,"RGBA").save(path,optimize=True)
def spec(x,sr,nper,fmax,path,cols=1200):
    f,t,Z=stft(x,fs=sr,nperseg=nper,noverlap=nper*3//4,window="hann")
    P=20*np.log10(np.abs(Z)+1e-9); P=P[f<=fmax]
    hi=P.max(); M=(P-(hi-80))/80                                       # 80 dB dynamic range
    im=Image.fromarray((np.clip(M,0,1)*255).astype(np.uint8)).resize((cols,M.shape[0]),Image.BILINEAR)
    alpha_png(np.asarray(im)/255,path,1.3)
    return f,t,P
x96,_=sf.read("attack_96k.wav",dtype="float64")
xf,_=sf.read("ffmpeg_16k.wav",dtype="float64"); xn,_=sf.read("naive_16k.wav",dtype="float64")
f,t,P=spec(x96,96000,2048,48000,"spec_file.png")
spec(xf,16000,512,8000,"spec_ffmpeg.png"); spec(xn,16000,512,8000,"spec_naive.png")
E=np.abs(np.fft.rfft(x96))**2; fr=np.fft.rfftfreq(len(x96),1/96000)
meta=json.load(open("audio_meta.json"))
meta["energy_frac_above_20k"]=round(float(E[fr>20000].sum()/E.sum()),4)
meta["energy_frac_32_40k"]=round(float(E[(fr>=32000)&(fr<40000)].sum()/E.sum()),4)
meta["peak_hz"]=round(float(fr[np.argmax(E)]),1)
# Whisper log-mel: n_fft 400, hop 160, hann, |STFT|^2 drop last frame, mel_80 filters, log10 clamp, max-8 floor, (x+4)/4
filters=np.load("mel_filters.npz")["mel_80"]
def logmel(x):
    w=np.hanning(401)[:-1]                                            # torch.hann_window(400) is periodic
    xp=np.pad(x,(200,200),mode="reflect")
    frames=np.lib.stride_tricks.sliding_window_view(xp,400)[::160]
    S=np.abs(np.fft.rfft(frames*w,axis=1))**2; S=S[:-1].T
    m=np.log10(np.clip(filters@S,1e-10,None)); m=np.maximum(m,m.max()-8.0); return (m+4)/4
for name,x in [("ffmpeg",xf),("naive",xn)]:
    m=logmel(x.astype(np.float32)); lo,hi=m.min(),m.max()
    alpha_png((m-lo)/(hi-lo),f"logmel_{name}.png",1.2)
    meta[f"logmel_{name}_shape"]=list(m.shape)
json.dump(meta,open("audio_meta.json","w"),indent=1); print(meta)
