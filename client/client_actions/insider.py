#!/usr/bin/env python
"""Support for statistical insider threat detection."""

from collections import namedtuple
from grr.client import actions
from grr.lib import rdfvalue
from grr.lib.rdfvalues.insider import InsiderStats
import bulkextractor
import json
import os
import os.path as path

class InsiderGather(actions.ActionPlugin):
  """Gather preselected filesystem statistics for later processing."""
  in_rdfvalue = None
  out_rdfvalue = InsiderStats

  def Run(self, unused_args):
    stats = dict()

    add_be_data(stats)
    add_py_data(stats)

    res = InsiderStats(initializer=json.dumps(stats))
    self.SendReply(res)

def add_be_data(stats):
  """
  Gather the stats bulk_extractor is responsible for and place them into the
  stats dict.
  """
  scanners = [ "email", "accts", "exif", "zip", "gzip", "rar", ]
      # "bulk",
  bulkextractor.soft_init(scanners)
  be = bulkextractor.Session()
  be.analyze_device("/dev/sda", 0.01, 65535)
  be.finalize()
  histograms = be.histograms()

  add_freq_uniq(stats, "Email", histograms["email_histogram"])
  add_freq_uniq(stats, "Edom", histograms["email_domain_histogram"])
  add_freq_uniq(stats, "CCN", histograms["ccn_histogram"])
  #add_freq_uniq(stats, "SSN", histograms["ccn_histogram"])
  add_freq_uniq(stats, "URL", histograms["url_histogram"])
  #add_freq_uniq(stats, "Udom", histograms["url_domain_histogram"])

def add_freq_uniq(stats, name, histogram):
  """
  For a given histogram, add stats for total count, (totfreq) total unique
  count (totuniq), and the frequencies of the top 10 histogram entries
  (01_totfreq..10_totfreq).
  """
  total = 0
  for entry in histogram:
    total += entry.count

  stats[name+"_totfreq"] = total
  stats[name+"_totuniq"] = len(histogram)
  for ii in range(10):
    key = "{}{:02d}_totfreq".format(name,ii+1)
    if ii < len(histogram):
      stats[key] = histogram[ii]
    else:
      stats[key] = bulkextractor.HistElem(count=0, feature=None)

def add_py_data(stats):
  """
  Gather the stats Python is responsible for and place them into the stats
  dict.
  """
  total_files = 0
  # file count per ptype
  ptype_files = dict.fromkeys(ptypes.keys(), 0)
  unknown_files = 0

  for dirpath, dirnames, filenames in os.walk("/"):
    for filename in filenames:
      total_files += 1

      _, ext = path.splitext(filename)
      # normalize extensions by removing dot and dropping case
      ext = ext[1:].lower()
      for ptype in extension_to_ptypes.get(ext, []):
        ptype_files[ptype] += 1
      if ext not in extension_to_ptypes:
        unknown_files += 1

  stats["Other_P"] = unknown_files
  for ptype, count in ptype_files.items():
    stats[ptype+"_P"] = count

"""
a PType is a collection of sceadan type integers and file extensions that
make up a _P insider stat, e.g. TIF_P which is made up of type 21 and the file
extensions .tif and .tiff.
"""
PType = namedtuple("PType", "sceadan_types file_extensions")
ptypes = {
    "JPG"         : PType([32], ["jpg", "jpeg"]),
    "Vid"         : PType([35, 36, 37, 38, 39, 42],
                          ["mov", "avi", "mp4", "mkv"]),
    "Text"        : PType([1, 3], ["txt", "log"]),
    "ASP"         : PType([6], ["asp", "aspx"]),
    "CSS"         : PType([10], ["css"]),
    "B64"         : PType([11], []),
    "B85"         : PType([12], []),
    "B16"         : PType([13], []),
    "URLencoded"  : PType([14], []),
    "PS"          : PType([15], []),
    "Email"       : PType([17, 18], ["pst", "ost", "pab", "msf"]),
    "PNG"         : PType([19], ["png"]),
    "TIF"         : PType([21], ["tif", "tiff"]),
    "JB2"         : PType([22], ["jb2", "jbig", "jbig2"]),
    "Zip"         : PType([23, 24, 27],
                          ["gz", "gzip", "tgz", "z", "taz", "zip", "bz2",
                           "bzip", "bzip2"]),
    "RPM"         : PType([26], ["rpm"]),
    "PDF"         : PType([28], ["pdf"]),
    "Audio"       : PType([33, 34, 40, 41],
                          ["mp3", "m4a", "aac", "wav", "wma"]),
    "EXE"         : PType([49], ["exe"]),
    "DLL"         : PType([50], ["dll"]),
    "ELF"         : PType([51], ["elf"]),
    "BMP"         : PType([52], ["bmp"]),
    "GIF"         : PType([20], ["gif"]),
    "WinSys"      : PType([],
                          ["inf", "pnf", "mof", "sys", "msi", "cfg", "chm",
                           "cab", "com", "hlp", "msc", "sdb", "fon", "cur",
                           "ax", "ttf", "query", "ver", "ott", "cat", "xcu",
                           "nls", "state", "dlg", "font"]),
    "Binary"      : PType([], ["bin", "dat"]),
    "Dev"         : PType([8, 9, 25],
                          ["js", "py", "pl", "c", "cpp", "h", "lib", "tcl",
                           "idx", "java", "jar", "class", "pm", "sh"]),
    "ini"         : PType([], ["ini"]),
    "Lnk"         : PType([], ["lnk"]),
    "Tmp"         : PType([], ["tmp"]),
    "Spreadsheet" : PType([2, 30, 44], ["csv", "xlsx", "xls", "ods"]),
    "Markup"      : PType([4, 5, 7], ["html", "htm", "xml", "json", "dtd"]),
    "WordProc"    : PType([16, 29, 43], ["rtf", "docx", "doc", "odt"]),
    "Present"     : PType([31, 45], ["pptx", "ppt", "odp"]),
}
def combined_ptype(*inputs):
  """Combine zero or more PTypes."""
  s_types = []
  f_exts = []
  for ptype in inputs:
    s_types += ptype.sceadan_types
    f_exts += ptype.file_extensions
  return PType(s_types, f_exts)

ptypes["JPG-vid"] = combined_ptype(ptypes["JPG"], ptypes["Vid"])

# The _to_ptype maps aid in quickly finding the apropriate ptype for a feature.
sceadan_to_ptypes = dict()
extension_to_ptypes = dict()
for typename, ptype in ptypes.items():
  # register this PType's sceadan types
  for s_type in ptype.sceadan_types:
    if s_type not in sceadan_to_ptypes:
      sceadan_to_ptypes[s_type] = list()
    sceadan_to_ptypes[s_type].append(typename)
  # register this PType's file extensions
  for ext in ptype.file_extensions:
    if ext not in extension_to_ptypes:
      extension_to_ptypes[ext] = list()
    extension_to_ptypes[ext].append(typename)
