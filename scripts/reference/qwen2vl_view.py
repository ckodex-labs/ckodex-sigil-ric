# Runs Qwen2-VL's own image processor (transformers 4.57.6, Qwen2VLImageProcessor, values from Qwen/Qwen2-VL-7B-Instruct preprocessor_config.json)
# on the attack file, then inverts the patch layout to recover the exact pixels the vision encoder receives.
import numpy as np, json, transformers
from PIL import Image
from transformers.models.qwen2_vl import image_processing_qwen2_vl as q
MEAN=np.array([0.48145466,0.4578275,0.40821073]); STD=np.array([0.26862954,0.26130258,0.27577711])
src=Image.open("tests/fixtures/multimodal/attack_source.png").convert("RGB")
p=q.Qwen2VLImageProcessor(min_pixels=3136,max_pixels=12845056,patch_size=14,temporal_patch_size=2,merge_size=2,image_mean=MEAN.tolist(),image_std=STD.tolist())
o=p(images=[src],return_tensors="np"); pv=o["pixel_values"]; t,gh,gw=[int(x) for x in o["image_grid_thw"][0]]
ps,ms,C,T=14,2,3,2
x=pv.reshape(t,gh//ms,gw//ms,ms,ms,C,T,ps,ps)          # layout used by the processor before flattening
x=x[0,:,:,:,:,:,0]                                        # first temporal copy (image is duplicated along T)
H,Wd=gh*ps,gw*ps
view=np.zeros((H,Wd,3))
for bh in range(gh//ms):
  for bw in range(gw//ms):
    for mh in range(ms):
      for mw in range(ms):
        patch=x[bh,bw,mh,mw]                              # (C,ps,ps)
        r=(bh*ms+mh)*ps; c=(bw*ms+mw)*ps
        view[r:r+ps,c:c+ps]=patch.transpose(1,2,0)
view=np.clip((view*STD+MEAN)*255+0.5,0,255).astype(np.uint8)
Image.fromarray(view).save("qwen_view.png")
meta={"transformers":transformers.__version__,"processor":"Qwen2VLImageProcessor","resample":"PIL bicubic (3)","source_px":list(src.size),
 "resized_px":[Wd,H],"grid_thw":[t,gh,gw],"patches":int(pv.shape[0]),"patch_values":int(pv.shape[1]),"merge":ms,
 "placeholders":int(t*gh*gw//ms//ms),"merged_grid":[gh//ms,gw//ms],
 "ids":{"vision_start":151652,"image_pad":151655,"vision_end":151653},"llm_hidden":3584,"vision_embed_dim":1280}
json.dump(meta,open("patches.json","w"),indent=1); print(meta)
