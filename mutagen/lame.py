################################################################################
#  Copyright (C) 2001  Ryan Finne <ryan@finnie.org>
#  Copyright (C) 2002-2012  Travis Shirk <travis@pobox.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
################################################################################

# gleefully lifted from eyeD3, with love.

from math import log10

import logging
log = logging.getLogger(__name__)

def bytes2bin(bytes, sz=8):
    '''Accepts a string of ``bytes`` (chars) and returns an array of bits
    representing the bytes in big endian byte order. An optional max ``sz`` for
    each byte (default 8 bits/byte) which can  be used to mask out higher
    bits.'''
    if sz < 1 or sz > 8:
        raise ValueError("Invalid sz value: %d" % sz)

    '''
    # I was willing to bet this implementation was gonna be faster, tis not
    retval = []
    for bite in bytes:
        bits = [int(b) for b in bin(ord(bite))[2:].zfill(8)][-sz:]
        assert(len(bits) == sz)
        retval.extend(bits)
    return retval
    '''

    retVal = []
    for b in bytes:
        bits = []
        b = ord(b)
        while b > 0:
            bits.append(b & 1)
            b >>= 1

        if len(bits) < sz:
            bits.extend([0] * (sz - len(bits)))
        elif len(bits) > sz:
            bits = bits[:sz]

        # Big endian byte order.
        bits.reverse()
        retVal.extend(bits)

    return retVal

def bin2dec(x):
    '''Convert ``x``, an array of "bits" (MSB first), to it's decimal value.'''
    bits = []
    bits.extend(x)
    bits.reverse()  # MSB

    multi = 1
    value = 0
    for b in bits:
        value += b * multi
        multi *= 2
    return value

class LameHeader(dict):

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

    def __init__(self, frame):
        """Read the LAME info tag.
        frame should be the first frame of an mp3.
        """
        self.decode(frame)

    def _crc16(self, data, val = 0):
        """Compute a CRC-16 checksum on a data stream."""
        for c in data:
            val = self._crc16_table[ord(c) ^ (val & 0xff)] ^ (val >> 8)
        return val

    def decode(self, frame):
        """Decode the LAME info tag."""
        try:
            pos = frame.index("LAME")
        except:
            return

        # check the info tag crc.Iif it's not valid, no point parsing much more.
        lamecrc = bin2dec(bytes2bin(frame[190:192]))
        if self._crc16(frame[:190]) != lamecrc:
            #log.debug('Lame tag CRC check failed')
            # read version string from the first 30 bytes, up to any
            # non-ascii chars, then strip padding chars.
            #
            # XXX (How many bytes is proper to read?  madplay reads 20, but I've
            # got files with longer version strings)
            lamever = []
            for c in frame[pos:pos + 30]:
                if ord(c) not in list(range(32, 127)):
                    break
                lamever.append(c)
            self['encoder_version'] = ''.join(lamever).rstrip('\x55')
            log.debug('Lame Encoder Version: %s' % self['encoder_version'])
            return

        log.debug('Lame info tag found at position %d' % pos)

        # Encoder short VersionString, 9 bytes
        self['encoder_version'] = lamever = frame[pos:pos + 9].rstrip()
        log.debug('Lame Encoder Version: %s' % self['encoder_version'])
        pos += 9

        # Info Tag revision + VBR method, 1 byte
        self['tag_revision'] = bin2dec(bytes2bin(frame[pos:pos + 1])[:5])
        vbr_method = bin2dec(bytes2bin(frame[pos:pos + 1])[5:])
        self['vbr_method'] = self.VBR_METHODS.get(vbr_method, 'Unknown')
        log.debug('Lame info tag version: %s' % self['tag_revision'])
        log.debug('Lame VBR method: %s' % self['vbr_method'])
        pos += 1

        # Lowpass filter value, 1 byte
        self['lowpass_filter'] = bin2dec(bytes2bin(frame[pos:pos + 1])) * 100
        log.debug('Lame Lowpass filter value: %s Hz' % self['lowpass_filter'])
        pos += 1

        # Replay Gain, 8 bytes total
        replaygain = {}

        # Peak signal amplitude, 4 bytes
        peak = bin2dec(bytes2bin(frame[pos:pos + 4])) << 5
        if peak > 0:
            peak /= float(1 << 28)
            db = 20 * log10(peak)
            replaygain['peak_amplitude'] = peak
            log.debug('Lame Peak signal amplitude: %.8f (%+.1f dB)' %
                      (peak, db))
        pos += 4

        # Radio and Audiofile Gain, AKA track and album, 2 bytes each
        for gaintype in ['radio', 'audiofile']:
            name = bin2dec(bytes2bin(frame[pos:pos + 2])[:3])
            orig = bin2dec(bytes2bin(frame[pos:pos + 2])[3:6])
            sign = bin2dec(bytes2bin(frame[pos:pos + 2])[6:7])
            adj  = bin2dec(bytes2bin(frame[pos:pos + 2])[7:]) / 10.0
            if sign:
                adj *= -1
            # XXX Lame 3.95.1 and above use 89dB as a reference instead of 83dB
            # as defined by the Replay Gain spec. Should this be compensated
            # for?
            # if lamever[:4] == 'LAME' and lamevercmp(lamever[4:], '3.95') > 0:
            #   adj -= 6
            if orig:
                name = self.REPLAYGAIN_NAME.get(name, 'Unknown')
                orig = self.REPLAYGAIN_ORIGINATOR.get(orig, 'Unknown')
                replaygain[gaintype] = {'name': name, 'adjustment': adj,
                                        'originator': orig}
                log.debug('Lame %s Replay Gain: %s dB (%s)' % (name, adj, orig))
            pos += 2
        if replaygain:
            self['replaygain'] = replaygain

        # Encoding flags + ATH Type, 1 byte
        encflags = bin2dec(bytes2bin(frame[pos:pos + 1])[:4])
        self['encoding_flags'], self['nogap'] = self._parse_encflags(encflags)
        self['ath_type'] = bin2dec(bytes2bin(frame[pos:pos + 1])[4:])
        log.debug('Lame Encoding flags: %s' % ' '.join(self['encoding_flags']))
        if self['nogap']:
            log.debug('Lame No gap: %s' % ' and '.join(self['nogap']))
        log.debug('Lame ATH type: %s' % self['ath_type'])
        pos += 1

        # if ABR {specified bitrate} else {minimal bitrate}, 1 byte
        btype = 'Constant'
        if 'Average' in self['vbr_method']:
            btype = 'Target'
        elif 'Variable' in self['vbr_method']:
            btype = 'Minimum'
        # bitrate may be modified below after preset is read
        self['bitrate'] = (bin2dec(bytes2bin(frame[pos:pos + 1])), btype)
        log.debug('Lame Bitrate (%s): %s' % (btype, self['bitrate'][0]))
        pos += 1

        # Encoder delays, 3 bytes
        self['encoder_delay'] = bin2dec(bytes2bin(frame[pos:pos + 3])[:12])
        self['encoder_padding'] = bin2dec(bytes2bin(frame[pos:pos + 3])[12:])
        log.debug('Lame Encoder delay: %s samples' % self['encoder_delay'])
        log.debug('Lame Encoder padding: %s samples' % self['encoder_padding'])
        pos += 3

        # Misc, 1 byte
        sample_freq = bin2dec(bytes2bin(frame[pos:pos + 1])[:2])
        unwise_settings = bin2dec(bytes2bin(frame[pos:pos + 1])[2:3])
        stereo_mode = bin2dec(bytes2bin(frame[pos:pos + 1])[3:6])
        self['noise_shaping'] = bin2dec(bytes2bin(frame[pos:pos + 1])[6:])
        self['sample_freq'] = self.SAMPLE_FREQUENCIES.get(sample_freq,
                                                          'Unknown')
        self['unwise_settings'] = bool(unwise_settings)
        self['stereo_mode'] = self.STEREO_MODES.get(stereo_mode, 'Unknown')
        log.debug('Lame Source Sample Frequency: %s' % self['sample_freq'])
        log.debug('Lame Unwise settings used: %s' % self['unwise_settings'])
        log.debug('Lame Stereo mode: %s' % self['stereo_mode'])
        log.debug('Lame Noise Shaping: %s' % self['noise_shaping'])
        pos += 1

        # MP3 Gain, 1 byte
        sign = bytes2bin(frame[pos:pos + 1])[0]
        gain = bin2dec(bytes2bin(frame[pos:pos + 1])[1:])
        if sign:
            gain *= -1
        self['mp3_gain'] = gain
        db = gain * 1.5
        log.debug('Lame MP3 Gain: %s (%+.1f dB)' % (self['mp3_gain'], db))
        pos += 1

        # Preset and surround info, 2 bytes
        surround = bin2dec(bytes2bin(frame[pos:pos + 2])[2:5])
        preset = bin2dec(bytes2bin(frame[pos:pos + 2])[5:])
        if preset in range(8, 321):
            if self['bitrate'] >= 255:
                # the value from preset is better in this case
                self['bitrate'] = (preset, btype)
                log.debug('Lame Bitrate (%s): %s' % (btype, self['bitrate'][0]))
            if 'Average' in self['vbr_method']:
                preset = 'ABR %s' % preset
            else:
                preset = 'CBR %s' % preset
        else:
            preset = self.PRESETS.get(preset, preset)
        self['surround_info'] = self.SURROUND_INFO.get(surround, surround)
        self['preset'] = preset
        log.debug('Lame Surround Info: %s' % self['surround_info'])
        log.debug('Lame Preset: %s' % self['preset'])
        pos += 2

        # MusicLength, 4 bytes
        self['music_length'] = bin2dec(bytes2bin(frame[pos:pos + 4]))
        log.debug('Lame Music Length: %s bytes' % self['music_length'])
        pos += 4

        # MusicCRC, 2 bytes
        self['music_crc'] = bin2dec(bytes2bin(frame[pos:pos + 2]))
        log.debug('Lame Music CRC: %04X' % self['music_crc'])
        pos += 2

        # CRC-16 of Info Tag, 2 bytes
        self['infotag_crc'] = lamecrc # we read this earlier
        log.debug('Lame Info Tag CRC: %04X' % self['infotag_crc'])
        pos += 2

    def _parse_encflags(self, flags):
        """Parse encoder flags.

        Returns a tuple containing lists of encoder flags and nogap data in
        human readable format.
        """

        encoder_flags, nogap = [], []

        if not flags:
            return encoder_flags, nogap

        if flags & self.ENCODER_FLAGS['NSPSYTUNE']:
            encoder_flags.append('--nspsytune')
        if flags & self.ENCODER_FLAGS['NSSAFEJOINT']:
            encoder_flags.append('--nssafejoint')

        NEXT = self.ENCODER_FLAGS['NOGAP_NEXT']
        PREV = self.ENCODER_FLAGS['NOGAP_PREV']
        if flags & (NEXT | PREV):
            encoder_flags.append('--nogap')
            if flags & PREV:
                nogap.append('before')
            if flags & NEXT:
                nogap.append('after')
        return encoder_flags, nogap

##
# \brief Compare LAME version strings.
#
# alpha and beta versions are considered older.
# Versions with sub minor parts or end with 'r' are considered newer.
#
# \param x The first version to compare.
# \param y The second version to compare.
# \returns Return negative if x<y, zero if x==y, positive if x>y.
def lamevercmp(x, y):
    x = x.ljust(5)
    y = y.ljust(5)
    if x[:5] == y[:5]:
        return 0
    ret = cmp(x[:4], y[:4])
    if ret:
        return ret
    xmaj, xmin = x.split('.')[:2]
    ymaj, ymin = y.split('.')[:2]
    minparts = ['.']
    # lame 3.96.1 added the use of r in the very short version for post releases
    if (xmaj == '3' and xmin >= '96') or (ymaj == '3' and ymin >= '96'):
        minparts.append('r')
    if x[4] in minparts:
        return 1
    if y[4] in minparts:
        return -1
    if x[4] == ' ':
        return 1
    if y[4] == ' ':
        return -1
    return cmp(x[4], y[4])

#                   MPEG1  MPEG2  MPEG2.5
SAMPLE_FREQ_TABLE = ((44100, 22050, 11025),
                     (48000, 24000, 12000),
                     (32000, 16000, 8000),
                     (None,  None,  None))

#              V1/L1  V1/L2 V1/L3 V2/L1 V2/L2&L3
BIT_RATE_TABLE = ((0,    0,    0,    0,    0),
                  (32,   32,   32,   32,   8),
                  (64,   48,   40,   48,   16),
                  (96,   56,   48,   56,   24),
                  (128,  64,   56,   64,   32),
                  (160,  80,   64,   80,   40),
                  (192,  96,   80,   96,   44),
                  (224,  112,  96,   112,  56),
                  (256,  128,  112,  128,  64),
                  (288,  160,  128,  144,  80),
                  (320,  192,  160,  160,  96),
                  (352,  224,  192,  176,  112),
                  (384,  256,  224,  192,  128),
                  (416,  320,  256,  224,  144),
                  (448,  384,  320,  256,  160),
                  (None, None, None, None, None))

#                             L1    L2    L3
TIME_PER_FRAME_TABLE = (None, 384, 1152, 1152)

# Emphasis constants
EMPHASIS_NONE = "None"
EMPHASIS_5015 = "50/15 ms"
EMPHASIS_CCIT = "CCIT J.17"

# Mode constants
MODE_STEREO              = "Stereo"
MODE_JOINT_STEREO        = "Joint stereo"
MODE_DUAL_CHANNEL_STEREO = "Dual channel stereo"
MODE_MONO                = "Mono"

# Xing flag bits
FRAMES_FLAG    = 0x0001
BYTES_FLAG     = 0x0002
TOC_FLAG       = 0x0004
VBR_SCALE_FLAG = 0x0008