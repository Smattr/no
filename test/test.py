#!/usr/bin/env python3

import os
import subprocess
import tempfile
import unittest

class Test(unittest.TestCase):

  def test_allow_network(self):
    '''
    test --allow-network
    '''

    # first check if we can ping example.com when uninstrumented
    try:
      subprocess.check_call(['ping', '-c', '1', 'example.com'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      self.skipTest('cannot ping example.com')

    # now confirm we can ping it when allowing network traffic
    subprocess.check_call(['no', '--allow-network', '--allow-writes', '--',
      'ping', '-c', '1', 'example.com'], stdout=subprocess.DEVNULL)

  def test_allow_writes(self):
    '''
    test --allow-writes
    '''

    with tempfile.TemporaryDirectory() as tmp:

      # try creating a file in this temporary directory
      foo = os.path.join(tmp, 'foo')
      p = subprocess.run(['no', '--allow-network', '--allow-writes', '--',
        'touch', foo], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertEqual(p.returncode, 0)

      # this should also succeed with network access disallowed
      p = subprocess.run(['no', '--allow-writes', '--', 'touch', foo],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertEqual(p.returncode, 0)

      # create a scratch file
      bar = os.path.join(tmp, 'bar')
      with open(bar, 'w') as f:
        f.write('hello world\n')

      # try appending to this file
      p = subprocess.run(['no', '--allow-network', '--allow-writes', '--',
        'tee', '-a', bar], input='an extra line\n', stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, universal_newlines=True)
      self.assertEqual(p.returncode, 0)

      # this should also succeed with network access disallowed
      p = subprocess.run(['no', '--allow-writes', '--', 'tee', '-a', bar],
        input='an extra line\n', stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, universal_newlines=True)
      self.assertEqual(p.returncode, 0)

  def test_disallow_network(self):
    '''
    test disallowing network access (the default)
    '''

    # first check if we can ping example.com when uninstrumented
    try:
      subprocess.check_call(['ping', '-c', '1', 'example.com'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      self.skipTest('cannot ping example.com')

    # now confirm we cannot ping it when disallowing network traffic
    p = subprocess.run(['no', '--allow-writes', '--', 'ping', '-c', '1',
      'example.com'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    self.assertNotEqual(p.returncode, 0)

  def test_disallow_writes(self):
    '''
    test disallowing file system writes (the default)
    '''

    with tempfile.TemporaryDirectory() as tmp:

      # try creating a file in this temporary directory
      foo = os.path.join(tmp, 'foo')
      p = subprocess.run(['no', '--allow-network', '--', 'touch', foo],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertNotEqual(p.returncode, 0)

      # this should also fail with network access disallowed
      p = subprocess.run(['no', '--', 'touch', foo],
          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertNotEqual(p.returncode, 0)

      # create a scratch file
      bar = os.path.join(tmp, 'bar')
      with open(bar, 'w') as f:
        f.write('hello world\n')

      # try appending to this file
      p = subprocess.run(['no', '--allow-network', '--', 'tee', '-a', bar],
        input='an extra line\n', stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, universal_newlines=True)
      self.assertNotEqual(p.returncode, 0)

      # this should also fail with network access disallowed
      p = subprocess.run(['no', '--', 'tee', '-a', bar],
        input='an extra line\n', stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, universal_newlines=True)
      self.assertNotEqual(p.returncode, 0)

if __name__ == '__main__':
  unittest.main()
