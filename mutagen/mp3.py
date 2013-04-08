# MP3 stream header information support for Mutagen.
# Copyright 2006 Joe Wreschnig
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.

"""MPEG audio stream information and tags."""

import os
import struct

from mutagen.id3 import ID3FileType, BitPaddedInt, delete

from lame import LameHeader

class error(RuntimeError): pass
class HeaderNotFoundError(error, IOError): pass
class InvalidMPEGHeader(error, IOError): pass

# Mode values.
STEREO, JOINTSTEREO, DUALCHANNEL, MONO = range(4)

class MPEGInfo(object):
    """MPEG audio stream information

    Parse information about an MPEG audio file. This also reads the
    Xing VBR header format.

    This code was implemented based on the format documentation at
    http://www.dv.co.yu/mpgscript/mpeghdr.htm.

    Useful attributes:
    length -- audio length, in seconds
    bitrate -- audio bitrate, in bits per second
    sketchy -- if true, the file may not be valid MPEG audio

    Useless attributes:
    version -- MPEG version (1, 2, 2.5)
    layer -- 1, 2, or 3
    mode -- One of STEREO, JOINTSTEREO, DUALCHANNEL, or MONO (0-3)
    protected -- whether or not the file is "protected"
    padding -- whether or not audio frames are padded
    sample_rate -- audio sample rate, in Hz
    """


    # from the LAME source:
    # http://lame.cvs.sourceforge.net/*checkout*/lame/lame/libmp3lame/VbrTag.c
    _crc16_table = [
      0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
      0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
      0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
      0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
      0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
      0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
      0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
      0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
      0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
      0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
      0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
      0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
      0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
      0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
      0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
      0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
      0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
      0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
      0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
      0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
      0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
      0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
      0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
      0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
      0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
      0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
      0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
      0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
      0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
      0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
      0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
      0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]

    ENCODER_FLAGS = {
      'NSPSYTUNE'   : 0x0001,
      'NSSAFEJOINT' : 0x0002,
      'NOGAP_NEXT'  : 0x0004,
      'NOGAP_PREV'  : 0x0008,}

    PRESETS = {
      0:    'Unknown',
      # 8 to 320 are reserved for ABR bitrates
      410:  'V9',
      420:  'V8',
      430:  'V7',
      440:  'V6',
      450:  'V5',
      460:  'V4',
      470:  'V3',
      480:  'V2',
      490:  'V1',
      500:  'V0',
      1000: 'r3mix',
      1001: 'standard',
      1002: 'extreme',
      1003: 'insane',
      1004: 'standard/fast',
      1005: 'extreme/fast',
      1006: 'medium',
      1007: 'medium/fast',}

    REPLAYGAIN_NAME = {
      0: 'Not set',
      1: 'Radio',
      2: 'Audiofile',}

    REPLAYGAIN_ORIGINATOR = {
      0:   'Not set',
      1:   'Set by artist',
      2:   'Set by user',
      3:   'Set automatically',
      100: 'Set by simple RMS average',}

    SAMPLE_FREQUENCIES = {
      0: '<= 32 kHz',
      1: '44.1 kHz',
      2: '48 kHz',
      3: '> 48 kHz',}

    STEREO_MODES = {
      0: 'Mono',
      1: 'Stereo',
      2: 'Dual',
      3: 'Joint',
      4: 'Force',
      5: 'Auto',
      6: 'Intensity',
      7: 'Undefined',}

    SURROUND_INFO = {
      0: 'None',
      1: 'DPL encoding',
      2: 'DPL2 encoding',
      3: 'Ambisonic encoding',
      8: 'Reserved',}

    VBR_METHODS = {
      0:  'Unknown',
      1:  'Constant Bitrate',
      2:  'Average Bitrate',
      3:  'Variable Bitrate method1 (old/rh)',
      4:  'Variable Bitrate method2 (mtrh)',
      5:  'Variable Bitrate method3 (mt)',
      6:  'Variable Bitrate method4',
      8:  'Constant Bitrate (2 pass)',
      9:  'Average Bitrate (2 pass)',
      15: 'Reserved',}

    # Map (version, layer) tuples to bitrates.
    __BITRATE = {
        (1, 1): range(0, 480, 32),
        (1, 2): [0, 32, 48, 56, 64, 80, 96, 112,128,160,192,224,256,320,384],
        (1, 3): [0, 32, 40, 48, 56, 64, 80, 96, 112,128,160,192,224,256,320],
        (2, 1): [0, 32, 48, 56, 64, 80, 96, 112,128,144,160,176,192,224,256],
        (2, 2): [0,  8, 16, 24, 32, 40, 48,  56, 64, 80, 96,112,128,144,160],
        }

    __BITRATE[(2, 3)] = __BITRATE[(2, 2)]
    for i in range(1, 4): __BITRATE[(2.5, i)] = __BITRATE[(2, i)]

    # Map version to sample rates.
    __RATES = {
        1: [44100, 48000, 32000],
        2: [22050, 24000, 16000],
        2.5: [11025, 12000, 8000]
        }

    sketchy = False

    def __init__(self, fileobj, offset=None):
        """Parse MPEG stream information from a file-like object.

        If an offset argument is given, it is used to start looking
        for stream information and Xing headers; otherwise, ID3v2 tags
        will be skipped automatically. A correct offset can make
        loading files significantly faster.
        """

        try: size = os.path.getsize(fileobj.name)
        except (IOError, OSError, AttributeError):
            fileobj.seek(0, 2)
            size = fileobj.tell()

        # If we don't get an offset, try to skip an ID3v2 tag.
        if offset is None:
            fileobj.seek(0, 0)
            idata = fileobj.read(10)
            try: id3, insize = struct.unpack('>3sxxx4s', idata)
            except struct.error: id3, insize = '', 0
            insize = BitPaddedInt(insize)
            if id3 == 'ID3' and insize > 0:
                offset = insize
            else: offset = 0

        # Try to find two valid headers (meaning, very likely MPEG data)
        # at the given offset, 30% through the file, 60% through the file,
        # and 90% through the file.
        for i in [offset, 0.3 * size, 0.6 * size, 0.9 * size]:
            try: self.__try(fileobj, int(i), size - offset)
            except error, e: pass
            else: break
        # If we can't find any two consecutive frames, try to find just
        # one frame back at the original offset given.
        else:
            self.__try(fileobj, offset, size - offset, False)
            self.sketchy = True

    def __try(self, fileobj, offset, real_size, check_second=True):
        # This is going to be one really long function; bear with it,
        # because there's not really a sane point to cut it up.
        fileobj.seek(offset, 0)

        # We "know" we have an MPEG file if we find two frames that look like
        # valid MPEG data. If we can't find them in 32k of reads, something
        # is horribly wrong (the longest frame can only be about 4k). This
        # is assuming the offset didn't lie.
        data = fileobj.read(32768)

        frame_1 = data.find("\xff")
        while 0 <= frame_1 <= len(data) - 4:
            frame_data = struct.unpack(">I", data[frame_1:frame_1 + 4])[0]
            if (frame_data >> 16) & 0xE0 != 0xE0:
                frame_1 = data.find("\xff", frame_1 + 2)
            else:
                version = (frame_data >> 19) & 0x3
                layer = (frame_data >> 17) & 0x3
                protection = (frame_data >> 16) & 0x1
                bitrate = (frame_data >> 12) & 0xF
                sample_rate = (frame_data >> 10) & 0x3
                padding = (frame_data >> 9) & 0x1
                private = (frame_data >> 8) & 0x1
                self.mode = (frame_data >> 6) & 0x3
                mode_extension = (frame_data >> 4) & 0x3
                copyright = (frame_data >> 3) & 0x1
                original = (frame_data >> 2) & 0x1
                emphasis = (frame_data >> 0) & 0x3
                if (version == 1 or layer == 0 or sample_rate == 0x3 or
                    bitrate == 0 or bitrate == 0xF):
                    frame_1 = data.find("\xff", frame_1 + 2)
                else: break
        else:
            raise HeaderNotFoundError("can't sync to an MPEG frame")

        # There is a serious problem here, which is that many flags
        # in an MPEG header are backwards.
        self.version = [2.5, None, 2, 1][version]
        self.layer = 4 - layer
        self.protected = not protection
        self.padding = bool(padding)

        self.bitrate = self.__BITRATE[(self.version, self.layer)][bitrate]
        self.bitrate *= 1000
        self.sample_rate = self.__RATES[self.version][sample_rate]

        if self.layer == 1:
            frame_length = (12 * self.bitrate / self.sample_rate + padding) * 4
            frame_size = 384
        else:
            frame_length = 144 * self.bitrate / self.sample_rate + padding
            frame_size = 1152

        if check_second:
            possible = frame_1 + frame_length
            if possible > len(data) + 4:
                raise HeaderNotFoundError("can't sync to second MPEG frame")
            frame_data = struct.unpack(">H", data[possible:possible + 2])[0]
            if frame_data & 0xFFE0 != 0xFFE0:
                raise HeaderNotFoundError("can't sync to second MPEG frame")

        frame_count = real_size / float(frame_length)
        samples = frame_size * frame_count
        self.length = samples / self.sample_rate

        # Try to find/parse the Xing header, which trumps the above length
        # and bitrate calculation.
        fileobj.seek(offset, 0)
        data = fileobj.read(32768)
        lame_header = LameHeader(data)
        print lame_header
        print data.index("LAME")
        try:
            xing = data[:-4].index("Xing")
        except ValueError:
            # Try to find/parse the VBRI header, which trumps the above length
            # calculation.
            try:
                vbri = data[:-24].index("VBRI")
            except ValueError: pass
            else:
                # If a VBRI header was found, this is definitely MPEG audio.
                self.sketchy = False
                vbri_version = struct.unpack('>H', data[vbri + 4:vbri + 6])[0]
                if vbri_version == 1:
                    frame_count = struct.unpack(
                        '>I', data[vbri + 14:vbri + 18])[0]
                    samples = frame_size * frame_count
                    self.length = (samples / self.sample_rate) or self.length
        else:
            # If a Xing header was found, this is definitely MPEG audio.
            self.sketchy = False
            flags = struct.unpack('>I', data[xing + 4:xing + 8])[0]
            if flags & 0x1:
                frame_count = struct.unpack('>I', data[xing + 8:xing + 12])[0]
                samples = frame_size * frame_count
                self.length = (samples / self.sample_rate) or self.length
            if flags & 0x2:
                bytes = struct.unpack('>I', data[xing + 12:xing + 16])[0]
                self.bitrate = int((bytes * 8) // self.length)

        # If the bitrate * the length is nowhere near the file
        # length, recalculate using the bitrate and file length.
        # Don't do this for very small files.
        fileobj.seek(2, 0)
        size = fileobj.tell()
        expected = (self.bitrate / 8) * self.length
        if not (size / 2 < expected < size * 2) and size > 2**16:
            self.length = size / float(self.bitrate * 8)

    def pprint(self):
        s = "MPEG %s layer %d, %d bps, %s Hz, %.2f seconds" % (
            self.version, self.layer, self.bitrate, self.sample_rate,
            self.length)
        if self.sketchy: s += " (sketchy)"
        return s

class MP3(ID3FileType):
    """An MPEG audio (usually MPEG-1 Layer 3) file."""

    _Info = MPEGInfo
    _mimes = ["audio/mp3", "audio/x-mp3", "audio/mpeg", "audio/mpg",
              "audio/x-mpeg"]

    def score(filename, fileobj, header):
        filename = filename.lower()
        return (header.startswith("ID3") * 2 + filename.endswith(".mp3") +
                filename.endswith(".mp2") + filename.endswith(".mpg") +
                filename.endswith(".mpeg"))
    score = staticmethod(score)

Open = MP3
