from distutils.core import setup

setup(name='unladen',
      version='0.0.0.242.1',
      description='Unladen object store',
      author='Ryan Finnie',
      author_email='ryan@finnie.org',
      url='https://github.com/rfinnie/unladen',
      packages=['unladen', 'unladen.httpd', 'unladen.httpd.handlers', 'unladen.utils'],
      scripts=['unladen_httpd']
     )

