import os
from html2image import Html2Image

hti = Html2Image()

# Try to set delay for Prism and fonts to load if the param exists, otherwise ignore
try:
    hti.screenshot(
        html_file='screen_raw_data.html',
        save_as='screen_raw_data.jpg',
        size=(1150, 1000)
    )
    
    hti.screenshot(
        html_file='screen_enriched_data.html',
        save_as='screen_enriched_data.jpg',
        size=(1250, 1600)
    )
    print("Screenshots created successfully!")
except Exception as e:
    print(f"Error: {e}")
