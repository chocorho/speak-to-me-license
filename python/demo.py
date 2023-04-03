#!/usr/bin/env python3
#
# Copyright (c) 2022 chozorho
# 
# Contact me if you want to copy, distribute, or republish this.
# 

import datetime
import getpass
#import os
import pathlib # new as of python 3.4
import pgpy
from pgpy import PGPMessage
import pgpy.errors
from pgpy.errors import PGPDecryptionError
import re

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By

import time

if ("__main__" == __name__):
  
  # Options -- taken from https://faun.pub/how-to-install-selenium-in-linux-e8928b2b709
  custom_gecko_options = Options()
  custom_gecko_options.add_argument("--headless")
  
  browser = webdriver.Firefox(options=custom_gecko_options)
  
  browser.get('https://themathjester.com/speak-to-me-verification.php')
  
  #assert "Compliance" in browser.title
  
  fields = browser.find_elements(By.TAG_NAME, "input")
  for f in fields:
    name_val = f.get_attribute("name")
    if (name_val is not None and name_val == "sixDigitCode"):
      code_val = f.get_attribute("value")
      print(code_val)
  
  name = str(input("Please enter the location of YOUR private key (this is secret!) $ "))
  phrase = getpass.getpass("Please enter your secret passphrase to uncover the key, or an empty string if not applicable. $ ")
  input_username = "AllLogarithmsEqual" 
  input_username = str(input("Please enter your username associated with the key. $ "))
  try:
    loaded_key,_ = pgpy.PGPKey.from_file(name)
  except Exception:
    print("Fatal Error: DRM check failed! (no private key?)");
    print("");
    print("In order to run this software, you must abide by the attached Speak-To-Me License.");
    print("That is, you must generate PGP Keys and contact chozorho ahead of time.");
    print("Send him your public key in order to become an authorized user!");
    browser.quit()
    exit()
  
  #loaded_key.parse()
  #print(dir(loaded_key))
  #print(loaded_key.is_unlocked)
  
  if ("" == phrase):
    assert not loaded_key.is_public
    assert not loaded_key.is_expired
    assert loaded_key.is_ascii
    signed = loaded_key.sign(str(code_val))
    r = datetime.date.today()
    print("Today\'s date has been read as %s" % (r))
    output_filename = "py-sign-result-"+str(r)+".gpg"
    output = open(output_filename, "wb")
    output.write(bytes(signed))
    output.close()
    print("finished writing signed (binary) file.")
  else:
    try:
      with loaded_key.unlock(phrase) as decrypted_key:
        #print(dir(decrypted_key))
        assert not decrypted_key.is_public
        assert not decrypted_key.is_expired
        assert decrypted_key.is_ascii
        #print(dir(decrypted_key.sign))
        print(str(code_val))
        #signed = decrypted_key.sign(str(code_val))
        pgp_m = pgpy.PGPMessage.new(str(code_val), cleartext=False) # True)
        #print(dir(pgpy.PGPMessage.new))
        #print(dir(pgpy.PGPMessage.message))
        #print(dir(pgpy.PGPMessage.parse))
        pgp_m |= decrypted_key.sign(pgp_m)
        r = datetime.date.today()
        print("Today\'s date has been read as %s" % (r))
        output_filename = "py-sign-result-"+str(r)+".gpg"
        output_f = open(output_filename, "wb") # YOU CHOOSE? "w" or "wb")
        output_f.write(bytes(pgp_m)) # YOU CHOOSE! str(pgp_m) OR bytes(pgp_m))
        output_f.close()
        print("finished writing signed (binary) file with decrypted key!")
    except pgpy.errors.PGPDecryptionError:
      print("Fatal Error: DRM check failed! (bad passphrase?)");
      print("");
      print("In order to run this software, you must abide by the attached Speak-To-Me License.");
      print("That is, you must generate PGP Keys and contact chozorho ahead of time.");
      print("Send him your public key in order to become an authorized user!");
      browser.quit()
      exit()
  
  file_web_upload = browser.find_element(By.ID, "signedBinary")
  abs_path = pathlib.Path() / output_filename
  #abs_path = os.path.join(os.getcwd(), output_filename)
  file_web_upload.send_keys(str(abs_path.resolve()))
  name_web_input = browser.find_element(By.ID, "username")
  name_web_input.send_keys(input_username)
  
  result = browser.find_element(By.ID, "submitBinary").click()
  
  response = browser.page_source
  
  print(response)

  matchObj = re.search("ACCEPTED", response)
  if (matchObj is not None):
    print("Flag found. You are an authorized user.")
  else:
    print("Fatal Error: DRM check failed!");
    print("");
    print("chozorho is sick and tired of people refusing to talk to him about technical topics.");
    print("Therefore, in order to run this software, you must abide by the attached Speak-To-Me License.");
    print("That is, you must contact chozorho directly ahead of time.");
    print("Send him your public key in order to become an authorized user!");
  
  browser.quit()
  
