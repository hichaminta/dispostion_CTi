from PIL import Image

path = "./logos/Telegram.png"
img = Image.open(path)
img = img.resize((300, 300), Image.LANCZOS)  # 150x150 pixels
img.save(path)
print(f"Resized to {img.size}")