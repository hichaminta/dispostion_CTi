@echo off
echo Deleting FeodoTracker JSON files...

del /q "C:\Users\Hicham\Desktop\PFE\dispostion_CTi\extraction_ioc_cve\tracking\feodotracker_tracking.json" 2>nul
del /q "C:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_cve_ioc\feodotracker_extracted.json" 2>nul
del /q "C:\Users\Hicham\Desktop\PFE\dispostion_CTi\Sources_data\feodotracker\feodotracker_*.json" 2>nul
del /q "C:\Users\Hicham\Desktop\PFE\dispostion_CTi\Sources_data\feodotracker\tracking.json" 2>nul

echo Done.
pause
