import shutil
src = r'c:\Users\chanv\Downloads\VIT Switch Website Design\src\index.css'
dst = r'c:\Users\chanv\Downloads\VIT Switch Website Design\flask_app\static\css\index.css'
shutil.copyfile(src, dst)
print('CSS copied successfully')
