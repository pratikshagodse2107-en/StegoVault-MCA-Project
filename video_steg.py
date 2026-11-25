import cv2
import numpy as np
from PIL import Image
import tempfile, os
from stego_engine import hide_secret_in_image, extract_secret_from_image

def hide_secret_in_video(video_bytes: bytes, secret_msg: str, password: str) -> bytes:
    """
    Reads an input video (MP4/AVI), embeds AES-256 encrypted payload into Frame 0
    using password-seeded Random LSB, and saves as a lossless AVI video.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp_in:
        tmp_in.write(video_bytes)
        in_path = tmp_in.name

    out_path = tempfile.NamedTemporaryFile(delete=False, suffix=".avi").name

    try:
        cap = cv2.VideoCapture(in_path)
        if not cap.isOpened():
            raise ValueError("Could not open the uploaded video file.")

        fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        # FFV1 is a true lossless video codec so LSB bits are never destroyed
        fourcc = cv2.VideoWriter_fourcc(*"FFV1")
        out = cv2.VideoWriter(out_path, fourcc, fps, (width, height))

        frame_idx = 0
        while True:
            ret, frame_bgr = cap.read()
            if not ret:
                break

            if frame_idx == 0:
                # Convert Frame 0 from BGR to RGB PIL Image and embed secret
                frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                pil_frame = Image.fromarray(frame_rgb)
                stego_pil, _ = hide_secret_in_image(
                    pil_frame, secret_msg.encode("utf-8"), password, filename="video_secret.txt", is_file=False
                )
                stego_bgr = cv2.cvtColor(np.array(stego_pil), cv2.COLOR_RGB2BGR)
                out.write(stego_bgr)
            else:
                out.write(frame_bgr)

            frame_idx += 1

        cap.release()
        out.release()

        if frame_idx == 0:
            raise ValueError("The uploaded video has zero readable frames.")

        with open(out_path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(in_path):
            os.remove(in_path)
        if os.path.exists(out_path):
            os.remove(out_path)

def extract_secret_from_video(stego_video_bytes: bytes, password: str) -> str:
    """Extracts Frame 0 from the lossless Stego AVI video and decrypts the secret message."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".avi") as tmp_vid:
        tmp_vid.write(stego_video_bytes)
        vid_path = tmp_vid.name

    try:
        cap = cv2.VideoCapture(vid_path)
        ret, frame_bgr = cap.read()
        cap.release()

        if not ret:
            raise ValueError("Unable to read frames from this video.")

        frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        pil_frame = Image.fromarray(frame_rgb)
        raw_bytes, _, _ = extract_secret_from_image(pil_frame, password)
        return raw_bytes.decode("utf-8")
    finally:
        if os.path.exists(vid_path):
            os.remove(vid_path)
