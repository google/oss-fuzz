#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# This script converts between OSS-Fuzz binary names and FFmpeg build targets.
# Context: https://github.com/google/oss-fuzz/issues/13472

import argparse
from enum import StrEnum, auto

# List of "legacy" decoders where we need to keep the existing name the same
# (ffmpeg_AV_CODEC_ID_<ID>_fuzzer).
# This is to ensure we don't break bisections, and don't have to migrate open
# testcases and corpora.
#
# Any new decoder fuzzer with an ID not in this list must have the format
# ffmpeg_AV_CODEC_ID_<ID>_DEC_fuzzer.
#
# Any new encoder fuzzer with an ID in this list (e.g. a new encoder was added
# where we previously only supported decoding) must have the format
# ffmpeg_AV_CODEC_ID_<ID>_ENC_fuzzer.
LEGACY_DECODERS = (
    'AAC_FIXED',
    'AAC_LATM',
    'AASC',
    'ACELP_KELVIN',
    'ADPCM_4XM',
    'ADPCM_AFC',
    'ADPCM_AGM',
    'ADPCM_AICA',
    'ADPCM_CT',
    'ADPCM_DTK',
    'ADPCM_EA',
    'ADPCM_EA_MAXIS_XA',
    'ADPCM_EA_R1',
    'ADPCM_EA_R2',
    'ADPCM_EA_R3',
    'ADPCM_EA_XAS',
    'ADPCM_IMA_ACORN',
    'ADPCM_IMA_APC',
    'ADPCM_IMA_CUNNING',
    'ADPCM_IMA_DAT4',
    'ADPCM_IMA_DK3',
    'ADPCM_IMA_DK4',
    'ADPCM_IMA_EA_EACS',
    'ADPCM_IMA_EA_SEAD',
    'ADPCM_IMA_ISS',
    'ADPCM_IMA_MOFLEX',
    'ADPCM_IMA_MTF',
    'ADPCM_IMA_OKI',
    'ADPCM_IMA_RAD',
    'ADPCM_IMA_SMJPEG',
    'ADPCM_IMA_XBOX',
    'ADPCM_MTAF',
    'ADPCM_PSX',
    'ADPCM_SBPRO_2',
    'ADPCM_SBPRO_3',
    'ADPCM_SBPRO_4',
    'ADPCM_THP',
    'ADPCM_THP_LE',
    'ADPCM_VIMA',
    'ADPCM_XA',
    'ADPCM_XMD',
    'ADPCM_ZORK',
    'AGM',
    'AIC',
    'ALS',
    'AMRNB',
    'AMRWB',
    'ANM',
    'ANSI',
    'APAC',
    'APE',
    'APV',
    'ARBC',
    'ARGO',
    'ATRAC1',
    'ATRAC3',
    'ATRAC3AL',
    'ATRAC3P',
    'ATRAC3PAL',
    'ATRAC9',
    'AURA',
    'AURA2',
    'AV1',
    'AVRN',
    'AVS',
    'BETHSOFTVID',
    'BFI',
    'BINK',
    'BINKAUDIO_DCT',
    'BINKAUDIO_RDFT',
    'BINTEXT',
    'BMV_AUDIO',
    'BMV_VIDEO',
    'BONK',
    'BRENDER_PIX',
    'C93',
    'CAVS',
    'CBD2_DPCM',
    'CCAPTION',
    'CDGRAPHICS',
    'CDTOONS',
    'CDXL',
    'CLEARVIDEO',
    'CLLC',
    'COOK',
    'CPIA',
    'CRI',
    'CSCD',
    'CYUV',
    'DDS',
    'DERF_DPCM',
    'DFA',
    'DIRAC',
    'DOLBY_E',
    'DSD_LSBF',
    'DSD_LSBF_PLANAR',
    'DSD_MSBF',
    'DSD_MSBF_PLANAR',
    'DSICINAUDIO',
    'DSICINVIDEO',
    'DSS_SP',
    'DST',
    'DVAUDIO',
    'DXA',
    'DXTORY',
    'EACMV',
    'EAMAD',
    'EATGQ',
    'EATGV',
    'EATQI',
    'EIGHTBPS',
    'EIGHTSVX_EXP',
    'EIGHTSVX_FIB',
    'ESCAPE124',
    'ESCAPE130',
    'EVRC',
    'FASTAUDIO',
    'FFWAVESYNTH',
    'FIC',
    'FLIC',
    'FMVC',
    'FOURXM',
    'FRAPS',
    'FRWU',
    'FTR',
    'G2M',
    'G729',
    'GDV',
    'GEM',
    'GREMLIN_DPCM',
    'GSM',
    'GSM_MS',
    'H263I',
    'H264',
    'HAP',
    'HCA',
    'HCOM',
    'HEVC',
    'HNM4_VIDEO',
    'HQX',
    'HQ_HQA',
    'HYMT',
    'IAC',
    'IDCIN',
    'IDF',
    'IFF_ILBM',
    'ILBC',
    'IMC',
    'IMM4',
    'IMM5',
    'INDEO2',
    'INDEO3',
    'INDEO4',
    'INDEO5',
    'INTERPLAY_ACM',
    'INTERPLAY_DPCM',
    'INTERPLAY_VIDEO',
    'IPU',
    'JACOSUB',
    'JV',
    'KGV1',
    'KMVC',
    'LAGARITH',
    'LEAD',
    'LOCO',
    'LSCR',
    'M101',
    'MACE3',
    'MACE6',
    'MDEC',
    'MEDIA100',
    'METASOUND',
    'MICRODVD',
    'MIMIC',
    'MISC4',
    'MJPEGB',
    'MMVIDEO',
    'MOBICLIP',
    'MOTIONPIXELS',
    'MP1',
    'MP1FLOAT',
    'MP2FLOAT',
    'MP3',
    'MP3ADU',
    'MP3ADUFLOAT',
    'MP3FLOAT',
    'MP3ON4',
    'MP3ON4FLOAT',
    'MPC7',
    'MPC8',
    'MPEG1_V4L2M2M',
    'MPEG2_V4L2M2M',
    'MPEGVIDEO',
    'MPL2',
    'MSA1',
    'MSCC',
    'MSMPEG4V1',
    'MSNSIREN',
    'MSP2',
    'MSS1',
    'MSS2',
    'MSZH',
    'MTS2',
    'MV30',
    'MVC1',
    'MVC2',
    'MVDV',
    'MVHA',
    'MWSC',
    'MXPEG',
    'NOTCHLC',
    'NUV',
    'ON2AVC',
    'OSQ',
    'PAF_AUDIO',
    'PAF_VIDEO',
    'PCM_F16LE',
    'PCM_F24LE',
    'PCM_LXF',
    'PCM_SGA',
    'PDV',
    'PGSSUB',
    'PGX',
    'PHOTOCD',
    'PICTOR',
    'PIXLET',
    'PJS',
    'PROSUMER',
    'PSD',
    'PTX',
    'QCELP',
    'QDM2',
    'QDMC',
    'QDRAW',
    'QOA',
    'QPEG',
    'RALF',
    'RASC',
    'RA_288',
    'REALTEXT',
    'RKA',
    'RL2',
    'RSCC',
    'RTV1',
    'RV30',
    'RV40',
    'RV60',
    'SAMI',
    'SANM',
    'SCPR',
    'SCREENPRESSO',
    'SDX2_DPCM',
    'SGA',
    'SGIRLE',
    'SHEERVIDEO',
    'SHORTEN',
    'SIMBIOSIS_IMX',
    'SIPR',
    'SIREN',
    'SMACKAUD',
    'SMACKER',
    'SMVJPEG',
    'SOL_DPCM',
    'SONIC',
    'SP5X',
    'SPEEX',
    'SRGC',
    'STL',
    'SUBVIEWER',
    'SUBVIEWER1',
    'SVQ3',
    'TAK',
    'TARGA_Y216',
    'TDSC',
    'THEORA',
    'THP',
    'TIERTEXSEQVIDEO',
    'TMV',
    'TRUEMOTION1',
    'TRUEMOTION2',
    'TRUEMOTION2RT',
    'TRUESPEECH',
    'TSCC',
    'TSCC2',
    'TWINVQ',
    'TXD',
    'ULTI',
    'V210X',
    'VB',
    'VBLE',
    'VC1',
    'VC1IMAGE',
    'VC1_V4L2M2M',
    'VCR1',
    'VMDAUDIO',
    'VMDVIDEO',
    'VMIX',
    'VMNC',
    'VP3',
    'VP4',
    'VP5',
    'VP6',
    'VP6A',
    'VP6F',
    'VP7',
    'VP8',
    'VP9',
    'VP9_V4L2M2M',
    'VPLAYER',
    'VQA',
    'VQC',
    'VVC',
    'WADY_DPCM',
    'WAVARC',
    'WCMV',
    'WEBP',
    'WMALOSSLESS',
    'WMAPRO',
    'WMAVOICE',
    'WMV3',
    'WMV3IMAGE',
    'WNV1',
    'WS_SND1',
    'XAN_DPCM',
    'XAN_WC3',
    'XAN_WC4',
    'XBIN',
    'XL',
    'XMA1',
    'XMA2',
    'XPM',
    'YLC',
    'YOP',
    'ZERO12V',
    'ZEROCODEC',
)


class IDType(StrEnum):
  DECODER = auto()
  ENCODER = auto()
  DEMUXER = auto()
  BSF = auto()
  OTHER = auto()


def binary_name(type: IDType, id: str) -> str:
  if type == IDType.OTHER:
    id = id.upper().replace('DEM', 'DEMUXER')
    return f'ffmpeg_{id}_fuzzer'

  if type == IDType.DEMUXER:
    id = id.upper()
    return f'ffmpeg_dem_{id}_fuzzer'

  if type == IDType.BSF:
    id = id.upper()
    return f'ffmpeg_BSF_{id}_fuzzer'

  if id in LEGACY_DECODERS:
    if type == IDType.DECODER:
      return f'ffmpeg_AV_CODEC_ID_{id}_fuzzer'
    if type == IDType.ENCODER:
      # New encoder got added where there was previously only a decoder.
      # Differentiate it.
      return f'ffmpeg_AV_CODEC_ID_{id}_ENC_fuzzer'

  if type == IDType.DECODER:
    # New decoder. Differentiate it.
    return f'ffmpeg_AV_CODEC_ID_{id}_DEC_fuzzer'

  # By default, encoder fuzzers will map to this.
  return f'ffmpeg_AV_CODEC_ID_{id}_fuzzer'


def build_target_name(binary_name: str) -> str:
  name = binary_name.removeprefix('ffmpeg_').removesuffix('_fuzzer')
  if name.startswith('AV_CODEC_ID_'):
    name = name.removeprefix('AV_CODEC_ID_')

    if name.endswith('_DEC') or name in LEGACY_DECODERS:
      name = name.removesuffix('_DEC')
      return f'target_dec_{name.lower()}_fuzzer'

    name = name.removesuffix('_ENC')
    return f'target_enc_{name.lower()}_fuzzer'

  return f'target_{name.lower().replace("demuxer", "dem")}_fuzzer'


def main():
  parser = argparse.ArgumentParser(
      description='FFmpeg fuzzer name mapping utility.')
  subparsers = parser.add_subparsers(dest='command',
                                     help='Available commands',
                                     required=True)

  binary_parser = subparsers.add_parser(
      'binary_name', help='Generate binary name for a codec ID and type.')
  binary_parser.add_argument(
      'type',
      type=IDType,
      choices=list(IDType),
      help='Type of ID (DECODER, ENCODER, DEMUXER, BSF, OTHER)')
  binary_parser.add_argument('id', type=str, help='Codec ID (e.g., AAC_FIXED)')
  binary_parser.set_defaults(
      func=lambda args: print(binary_name(args.type, args.id)))

  target_parser = subparsers.add_parser(
      'build_target_name',
      help='Generate build target name from a binary name.')
  target_parser.add_argument(
      'name',
      type=str,
      help='Binary name (e.g., ffmpeg_AV_CODEC_ID_AAC_FIXED_fuzzer)')
  target_parser.set_defaults(
      func=lambda args: print(build_target_name(args.name)))

  args = parser.parse_args()
  args.func(args)


if __name__ == '__main__':
  main()
