#!/usr/bin/env python3

import subprocess
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
    subprocess.check_call(
      ['no', '--allow-network', '--', 'ping', '-c', '1', 'example.com'],
      stdout=subprocess.DEVNULL)

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
    try:
      subprocess.check_call(['no', '--', 'ping', '-c', '1', 'example.com'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.fail('ping succeeded with network access denied')
    except subprocess.CalledProcessError:
      pass

if __name__ == '__main__':
  unittest.main()
