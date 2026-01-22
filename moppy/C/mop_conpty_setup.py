from setuptools import setup, Extension

ext = Extension(
    'mop_conpty',
    sources=['mop_conpty.cpp'],
    libraries=['kernel32', 'user32', 'advapi32'],
)

setup(
    name='mop_conpty',
    ext_modules=[ext],
)
