######################################################################
#
# Copyright 2007, 2008 Zenoss, Inc.  All Rights Reserved.
#
######################################################################

import Globals
from Products.CMFCore.DirectoryView import registerDirectory

skinsDir = os.path.join(os.path.dirname(__file__), 'skins')
if os.path.isdir(skinsDir):
    registerDirectory(skinsDir, globals())
