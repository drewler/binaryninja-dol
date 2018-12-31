
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.types import Symbol, Type
from binaryninja.enums import (BranchType, InstructionTextTokenType, LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType)
from binaryninja.interaction import get_open_filename_input, get_choice_input

import struct
import importlib

# Based on IDA DOL loader from http://hitmen.c02.at/html/gc_tools.html

# typedef struct {
#   unsigned int offsetText[7];
#   unsigned int offsetData[11];
#   unsigned int addressText[7];
#   unsigned int addressData[11];
#   unsigned int sizeText[7];
#   unsigned int sizeData[11];
#   unsigned int addressBSS;
#   unsigned int sizeBSS;
#   unsigned int entrypoint;
# } dolhdr;

class DOLView(BinaryView):
    name = "DOLView"
    long_name = "DOL file"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform= Architecture['ppc'].standalone_platform

    def read_header(self):
        self.header = {}
        cursor = 0
        self.header['offsetText'] = struct.unpack(">7I", self.parent_view.read(0, 7*4))
        cursor += 7*4
        self.header['offsetData'] = struct.unpack(">11I", self.parent_view.read(cursor, 11*4))
        cursor += 11*4
        self.header['addressText'] = struct.unpack(">7I", self.parent_view.read(cursor, 7*4))
        cursor += 7*4
        self.header['addressData'] = struct.unpack(">11I", self.parent_view.read(cursor, 11*4))
        cursor += 11*4
        self.header['sizeText'] = struct.unpack(">7I", self.parent_view.read(cursor, 7*4))
        cursor += 7*4
        self.header['sizeData'] = struct.unpack(">11I", self.parent_view.read(cursor, 11*4))
        cursor += 11*4
        self.header['addressBSS'] = struct.unpack(">I", self.parent_view.read(cursor, 4))[0]
        cursor += 4
        self.header['sizeBSS'] = struct.unpack(">I", self.parent_view.read(cursor, 4))[0]
        cursor += 4
        self.header['entrypoint'] = struct.unpack(">I", self.parent_view.read(cursor, 4))[0]

        print self.header

    def init(self):

        # read header
        self.read_header()

        # create code segments
        for i in range(7):
            if self.header['addressText'][i] == 0:
                continue
            
            self.add_auto_segment(
                self.header['addressText'][i],
                self.header['sizeText'][i],
                self.header['offsetText'][i],
                self.header['sizeText'][i],
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
            )

        # create data segments
        for i in range(7):
            if self.header['addressData'][i] == 0:
                continue
            
            self.add_auto_segment(
                self.header['addressData'][i],
                self.header['sizeData'][i],
                self.header['offsetData'][i],
                self.header['sizeData'][i],
                SegmentFlag.SegmentReadable
            )

        if self.header['addressBSS']:
            self.add_auto_segment(
                self.header['addressBSS'],
                self.header['sizeBSS'],
                0,
                0,
                SegmentFlag.SegmentReadable
            )

        self.add_entry_point(self.header['entrypoint'])
        return True

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def perform_get_entry_point(self):
        return self.header['entrypoint']

print list(Architecture)

DOLView.register()
