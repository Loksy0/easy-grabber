from setuptools import setup, find_packages

setup(
    name='easy-grabber',  
    version='1.5',  
    packages=find_packages(),  
    install_requires=[
        'opencv-python',  
        'pycryptodome',    
        'requests',        
        'pyautogui',        
        'pywin32',        
        'urllib3',          
    ],
    entry_points={  
        'console_scripts': [
        ],
    },
    author='Loksy',
    author_email='example@example.com',
    description='Modu to make life easier',
    url='https://github.com/Loksy0/easy-grabber',
)