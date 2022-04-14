# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Module that uses XYZ tool to parse metadata from zip files.
# Configuration settings:
#   meta_zip_verbosity: An integer representing the verbosity of the metadata
#       that should be extracted. The settings are as follows:
#       1 - only fingerprints
#       2 - fingerprints + xyz verbosity 0
#       3 - fingerprints + xyz verbosity 1
#       4 - fingerprints + xyz verbosity 2
#       5 - fingerprints + xyz verbosity 3 (no change from verbosity == 4 currently)
#       6 - fingerprints + xyz verbosity 4 (no change from verbosity == 4 currently)
#   meta_zip_derive_deflate_level: Boolean value on whether xyz tool should be used to derive
#       the deflate level using XYZ tool.
# Library dependencies: XYZ.py (zip tool)
from future import standard_library
standard_library.install_aliases()
from laikaboss.si_module import SI_MODULE
from laikaboss import config
from laikaboss import xyz
from collections import Counter
import io

class META_ZIP(SI_MODULE):
  '''
  Input: A zip file to be analyzed by XYZ tool.
  Output: None. Adds module metadata about the object and flags if appropriate.

  Purpose: Extract metadata from zip files, and try and use it to fingerprint certain
  zip creation tools. 
  '''
  def __init__(self,):
    self.module_name = "META_ZIP"
    # Verbosity options (note does not support hex dumping like xyz CLI):
    # 1 - only fingerprints
    # 2 - fingerprints + xyz verbosity 0
    # 3 - fingerprints + xyz verbosity 1
    # 4 - fingerprints + xyz verbosity 2
    # 5 - fingerprints + xyz verbosity 3 (no change from verbosity == 4 currently)
    # 6 - fingerprints + xyz verbosity 4 (no change from verbosity == 4 currently)
    self.verbosity = 6
    if hasattr(config, 'meta_zip_verbosity'):
        self.verbosity = config.verbosity
    self.derive_deflate_level = False
    if hasattr(config, 'meta_zip_derive_deflate_level'):
        self.verbosity = config.derive_deflate_level

  def _run(self, scanObject, result, depth, args):
    moduleResult = []
    archive = xyz.parse_zip(io.BytesIO(scanObject.buffer), derive_deflate_level=self.derive_deflate_level)

    # Append metadata / flags to the archive
    if archive:
      # Debug info available via XYZ
      #print '\n----- Full Info Aval -----'
      #for k,v in archive.iteritems():
      #    print k,v
      #print '----- End Full Info Aval -----\n'

      # Determine what file metadata will be added at this verbosity
      fields_to_log = []
      if(self.verbosity >= 2):
        fields_to_log += [  'create_ver',
                              'create_sys',
                              'extract_ver',
                              'flags_short',
                              'method',
                              'time',
                              'date',
                              'crc',
                              'c_size',
                              'u_size',
                              'fname_len',
                              'extra_len',
                              'comment_len',
                              'disk_num',
                              'int_attr',
                              'ext_attr_dos',
                              'ext_attr_posix',
                              'extra_types',
                              'filename']
      if(self.verbosity >= 3):
        fields_to_log += [  'comment',
                              'flags',
                              'l_extra_types',
                              'local_central_header_deltas']
      if(self.verbosity >= 4):
        fields_to_log += [  'l_extra_ver',
                              'l_flags_short',
                              'l_method',
                              'l_time',
                              'l_date',
                              'l_crc',
                              'l_c_size',
                              'l_u_size',
                              'l_fname_len',
                              'l_extra_len',
                              'l_filename',
                              'desc_crc',
                              'desc_c_size',
                              'desc_u_size',
                              'l_flags',
                              'compress_flags']
      if(self.derive_deflate_level):
        fields_to_log += [  'derived_deflate_level_max',
                              'derived_deflate_level_min',
                              'derived_deflate_match']

      # Get contained files data
      files = archive.get('files')

      # Set up counters to go through children file metadata to profile / set flags
      versions = Counter()
      create_sys = Counter()
      ext_attrs = Counter()
      dates = Counter()
      overflow_in_seconds = False
      ZipSlip_Identifers = ['../', '..\\']
      ZipSlip_Vulnerability = False

      # For each file, record its create_ver/sys, posix attributes.
      # In addition check for overflow in the seconds of timestamp (indicating a zip
      # Potentially crafted by metasploit)
      contained_files_meta = []
      for file in files:
        # Append the fields given by verbosity setting
        file_info = dict()
        for field in fields_to_log:
          field_val = file.get(field)
          if field_val is not None:
            file_info[field] = field_val
        contained_files_meta.append(file_info)

        # Get data for counters used in fingerprinting
        versions[file.get('create_ver')] += 1
        create_sys[file.get('create_sys')] += 1
        ext_attrs[file.get('ext_attr_posix')] += 1
        time = file.get('time')
        if (not overflow_in_seconds):
          if time:
            #print int(time.split(':')[2])
            if(int(time.split(':')[2]) > 59):
              overflow_in_seconds = True
        dates[file.get('date')] += 1

        # Check filenames for potential Zip Slip archives
        if(not ZipSlip_Vulnerability): # Stop checking if we identify one ZipSlip Document
          file_name = file.get('filename')
          if file_name:
            # Check for relitive path Zip Slip
            if any(x in file_name for x in ZipSlip_Identifers):
              ZipSlip_Vulnerability = True
            # Check for absolute path Zip Slip
            elif ((file_name[0] == '/') or (file_name[0] == '\\')):
              ZipSlip_Vulnerability = True
      # Add the desired contained files metadata
      scanObject.addMetadata(self.module_name, 'contained_files_meta', contained_files_meta)

      # Get comment metadata if exists (might be redundant/same as value found in end_dir)
      if(self.verbosity >= 2):
        comment = archive.get('comment')
        if comment:
          scanObject.addMetadata(self.module_name, 'zip_file_comment', comment)

      # Add end_dir_info if applicable
      if(self.verbosity >= 4):
        for end_dir_type in ['end_dir', 'loc_dir64', 'end_dir64']:
          if end_dir_type in archive:
            end_dir_info = archive.get(end_dir_type)
            for k,v in end_dir_info.items():
              scanObject.addMetadata(self.module_name, k, v)

      if(self.verbosity >= 1):
        # Check if overflow was found in any of the timestamps
        if(overflow_in_seconds):
          scanObject.addFlag('m_zip:overflow_in_timestamp_metasploit')

        # Check if zipslip strings exist in filenames
        if(ZipSlip_Vulnerability):
          scanObject.addFlag('m_zip:zip_slip_vulnerability')

        # Check for version irregularities
        if(len(list(versions.items())) != 1):
          scanObject.addFlag('m_zip:multiple_create_versions')
          version = -1
        else:
          version = list(versions.items())[0][0]

        # Check for create sys irregularities
        if(len(list(create_sys.items())) != 1):
          scanObject.addFlag('m_zip:multiple_createsys')
          create_sys_type = 'multiple'
        else:
          create_sys_type = list(create_sys.items())[0][0]

        # Try and fingerprint certain document creator tools, Ex: Microsoft Office/metasploit
        if(ext_attrs.most_common(1)[0][0] == '----------'):
          # Check for microsoft word (this can probably be loosened)
          if(create_sys_type == 'FAT'):
            if(version == 45):
              if(dates.most_common(1)[0][0] == '1980-01-01'):
                first_file_name = files[0].get('filename')
                if(first_file_name):
                  if(first_file_name == '[Content_Types].xml'):
                    # At this point it really should be a document created by Microsoft Office
                    scanObject.addFlag('m_zip:microsoft_office_document')

          # Check for a metasploit zip
          if(len(list(ext_attrs.items())) == 1):
            # Check more things to indicate Metasploit creator
            if(version == 20):
              if(create_sys_type == 'FAT'):
                # Check for normal deflate specified, canonical max deflate used
                meta_sploit_default_flags = False
                for file in files:
                  flags = file.get('flags')
                  if(flags): # Fix store with whatever
                    meta_sploit_default_flags = True
                    if(('deflate_normal' in flags) or ('store' in flags)):
                      continue
                    else:
                      meta_sploit_default_flags = False

                if (meta_sploit_default_flags):
                  if(overflow_in_seconds):
                    scanObject.addFlag('m_zip:overflow_in_timestamp_metasploit')
                  else:
                    scanObject.addFlag('m_zip:possible_metasploit_zip')
          else:
            scanObject.addFlag('m_zip:no_permission_mixed_zip')

    return moduleResult

  def _close(self):
    pass
