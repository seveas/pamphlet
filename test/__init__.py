import sys, os
import distutils.util
from whelk import shell

test_root = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(test_root)
sys.path.insert(0, os.path.join(root, 'build', 'lib.%s-%s' % (distutils.util.get_platform(), sys.version[0:3])))
sys.path.insert(0, root)

# Make sure our fake open/fopen are loaded so we can override the pam config
# and password database
shell.make('-C', test_root, redirect=False, raise_on_error=True)
if 'LD_PRELOAD' not in os.environ:
    os.environ['LD_LIBRARY_PATH'] = test_root
    os.environ['LD_PRELOAD'] ='fake_open.so'
    os.environ['TEST_ETC'] = os.path.join(test_root, 'etc')
    args = sys.argv
    if args[0].endswith('-m unittest'):
        args = args[0].rsplit(None, 2) + args[1:]
    os.execve(sys.executable, args, os.environ)
