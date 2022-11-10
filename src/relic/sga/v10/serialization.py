"""
Binary Serializers for Relic's SGA-V10
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO, Dict, Tuple, cast

from serialization_tools.structx import Struct
from relic.core.errors import MismatchError
from relic.sga.core import serialization as _s
from relic.sga.core.definitions import StorageType, VerificationType
from relic.sga.core.filesystem import registry
from relic.sga.core.protocols import StreamSerializer
from relic.sga.core.serialization import (
    FileDef as BaseFileDef,
    ArchivePtrs,
    TocBlock,
    TOCSerializationInfo,
)
from relic.sga.v10.definitions import version


@dataclass
class TocFooter:
    unk_a: int
    unk_b: int
    block_size: int


class EncryptionType(IntEnum):
    NONE = 0
    AES128 = 1


@dataclass
class FileDef(BaseFileDef):
    # modified: datetime
    verification: VerificationType
    encryption: EncryptionType
    crc: int
    hash_pos: int


class FileDefSerializer(StreamSerializer[FileDef]):
    """
    Serializes File information using the V9 format.
    """

    STORAGE_MASK = 0x0F
    ENCRYPTION_MASK = 0xF0
    ENCRYPTION_SHIFT = 4

    def __init__(self, layout: Struct):
        self.layout = layout

    def unpack(self, stream: BinaryIO) -> FileDef:
        """Unpacks a File Definition from the stream."""
        (
            name_rel_pos,
            hash_pos,
            data_rel_pos,
            length_in_archive,
            length_on_disk,
            # modified_seconds,
            verification_type_val,
            storage_and_encryption_flags,
            crc,
        ) = self.layout.unpack_stream(stream)

        storage_value = storage_and_encryption_flags & self.STORAGE_MASK
        encryption_value = (
            storage_and_encryption_flags & self.ENCRYPTION_MASK
        ) >> self.ENCRYPTION_SHIFT
        storage_type: StorageType = StorageType(storage_value)
        encryption_type = EncryptionType(encryption_value)  # None / AES128
        verification_type: VerificationType = VerificationType(verification_type_val)
        return FileDef(
            name_pos=name_rel_pos,
            data_pos=data_rel_pos,
            length_on_disk=length_on_disk,
            length_in_archive=length_in_archive,
            storage_type=storage_type,
            # modified=modified,
            encryption=encryption_type,
            verification=verification_type,
            crc=crc,
            hash_pos=hash_pos,
        )

    def pack(self, stream: BinaryIO, value: FileDef) -> int:
        # modified: int = int(value.modified.timestamp())
        storage_type = value.storage_type.value  # convert enum to value
        encryption_type: int = value.encryption.value
        verification_type = value.verification.value  # convert enum to value
        storage_and_encryption_flags = (
            encryption_type << self.ENCRYPTION_SHIFT
        ) | storage_type
        args = (
            value.name_pos,
            value.hash_pos,
            value.data_pos,
            value.length_in_archive,
            value.length_on_disk,
            verification_type,
            storage_and_encryption_flags,
            # modified,
            value.crc,
        )
        written: int = self.layout.pack_stream(stream, *args)
        return written


@dataclass
class MetaBlock(_s.MetaBlock):
    """
    Container for header information used by V9
    """

    name: str
    ptrs: ArchivePtrs
    sha_256: bytes

    @classmethod
    def default(cls) -> MetaBlock:
        """Returns a Default, 'garbage' instance which can be used as a placeholder for write-backs."""
        default_sha256: bytes = b"".join([b"default hash.   "] * 16)
        return cls("Default Meta Block", ArchivePtrs.default(), default_sha256)


@dataclass
class ArchiveHeaderSerializer(StreamSerializer[MetaBlock]):
    """
    Serializer to convert header information to it's dataclass; ArchiveHeader
    """

    layout: Struct

    ENCODING = "utf-16-le"
    RSV_0 = 0
    RSV_1 = 1

    def unpack(self, stream: BinaryIO) -> MetaBlock:
        """Unpacks a MetaBlock from the stream."""
        (
            encoded_name,  # EngineArtHigh
            header_pos,  # 0e59 ~ 8b
            header_size,  # 03b1 ~ 4b
            data_pos,  # 01ac ~ 8b
            data_size,  # 0cad ~ 4b
            rsv_0,  # 0 ~ 4b
            rsv_1,  # 1 ~ 4b
            sha_256,  # 256b of something (following is 0x78 0xda (zlib header) & @ 0x01ac)
        ) = self.layout.unpack_stream(stream)
        name = encoded_name.decode(self.ENCODING).rstrip("\0")
        ptrs = ArchivePtrs(header_pos, header_size, data_pos, data_size)
        if (rsv_0, rsv_1) != (self.RSV_0, self.RSV_1):
            raise MismatchError(
                "Reserved Flags", (rsv_0, rsv_1), (self.RSV_0, self.RSV_1)
            )

        return MetaBlock(name, ptrs, sha_256=sha_256)

    def pack(self, stream: BinaryIO, value: MetaBlock) -> int:
        """Packs a MetaBlock into the stream."""
        encoded_name = value.name.encode(self.ENCODING)
        args = (
            encoded_name,
            value.ptrs.header_pos,
            value.ptrs.header_size,
            value.ptrs.data_pos,
            value.ptrs.data_size,
            self.RSV_0,
            self.RSV_1,
            value.sha_256,
        )
        written: int = self.layout.pack_stream(stream, *args)
        return written


@dataclass
class TocFooterSerializer(StreamSerializer[TocFooter]):
    layout: Struct

    def unpack(self, stream: BinaryIO) -> TocFooter:
        (unk_a, unk_b, block_size) = self.layout.unpack_stream(stream)

        return TocFooter(unk_a, unk_b, block_size)

    def pack(self, stream: BinaryIO, value: TocFooter) -> int:
        args = (value.unk_a, value.unk_b, value.block_size)
        written: int = self.layout.pack_stream(stream, *args)
        return written


def assemble_meta(
    _: BinaryIO, header: MetaBlock, footer: TocFooter
) -> Dict[str, object]:
    """Extracts information from the meta-block to a dictionary the FS can store."""
    return {
        "sha_256": header.sha_256.hex(),
        "unk_a": footer.unk_a,
        "unk_b": footer.unk_b,
        "block_size": footer.block_size,
    }


def disassemble_meta(
    _: BinaryIO, metadata: Dict[str, object]
) -> Tuple[MetaBlock, TocFooter]:
    """Converts the archive's metadata dictionary into a MetaBlock class the Serializer can use."""
    meta = MetaBlock(
        None,  # type: ignore
        None,  # type: ignore
        sha_256=bytes.fromhex(cast(str, metadata["sha_256"])),
    )
    footer = TocFooter(
        unk_a=cast(int, metadata["unk_a"]),
        unk_b=cast(int, metadata["unk_b"]),
        block_size=cast(int, metadata["block_size"]),
    )
    return meta, footer


# def recalculate_sha256(stream: BinaryIO, meta: MetaBlock) -> None:
#     # Do nothing; we don't know how to do this yet
#     # TODO
#     pass


def meta2def(meta: Dict[str, object]) -> FileDef:
    """
    Converts metadata to a File Definitions
    """
    verification = VerificationType(cast(int, meta["verification_type"]))
    encryption = EncryptionType(cast(int, meta["encryption_type"]))
    storage_type = StorageType(cast(int, meta["storage_type"]))
    hash_pos = cast(int, meta["hash_pos"])
    crc = cast(int, meta["crc"])
    return FileDef(
        None,  # type: ignore
        None,  # type: ignore
        None,  # type: ignore
        None,  # type: ignore
        storage_type=storage_type,
        # modified=modified,
        verification=verification,
        encryption=encryption,
        hash_pos=hash_pos,
        crc=crc,
    )


def def2meta(_def: FileDef) -> Dict[str, object]:
    # modified_seconds = int(time.mktime(_def.modified.timetuple()))
    encryption = int(_def.encryption)
    verification = int(_def.verification)
    storage_type = int(_def.storage_type)
    return {
        "storage_type": storage_type,
        "verification_type": verification,
        "encryption_type": encryption,
        "hash_pos": _def.hash_pos,
        "crc": _def.crc,
    }


class EssenceFSSerializer(_s.EssenceFSSerializer[FileDef, MetaBlock, TocFooter]):
    """
    Serializer to read/write an SGA file to/from a stream from/to a SGA File System
    """

    def __init__(
        self,
        toc_serializer: StreamSerializer[TocBlock],
        toc_footer_serializer: StreamSerializer[TocFooter],
        meta_serializer: StreamSerializer[MetaBlock],
        toc_serialization_info: TOCSerializationInfo[FileDef],
    ):
        super().__init__(
            version=version,
            meta_serializer=meta_serializer,
            toc_serializer=toc_serializer,
            toc_meta_serializer=toc_footer_serializer,
            toc_serialization_info=toc_serialization_info,
            assemble_meta=assemble_meta,
            disassemble_meta=disassemble_meta,
            build_file_meta=def2meta,
            gen_empty_meta=MetaBlock.default,
            finalize_meta=lambda _, __: None,
            meta2def=meta2def,
        )


_folder_layout = Struct("<5I")
_folder_serializer = _s.FolderDefSerializer(_folder_layout)

_drive_layout = Struct("<64s 64s 5I")
_drive_serializer = _s.DriveDefSerializer(_drive_layout)

_file_layout = Struct("<2I Q 2I 2B I")
_file_serializer = FileDefSerializer(_file_layout)

_toc_layout = Struct("<8I")
_toc_header_serializer = _s.TocHeaderSerializer(_toc_layout)
# 0x002c ~ 0x0001 ~ Drive
# 0x00c0 ~ 0x000a ~ Folder
# 0x0188 ~ 0x0007 ~ Files
# 0x025a ~ 0x0157 ~ Names

_toc_footer_layout = Struct("<3I")
_toc_footer_serializer = TocFooterSerializer(_toc_footer_layout)
_meta_header_layout = Struct("<128s QI QI 2I 256s")
_meta_header_serializer = ArchiveHeaderSerializer(_meta_header_layout)

essence_fs_serializer = EssenceFSSerializer(
    meta_serializer=_meta_header_serializer,
    toc_serializer=_toc_header_serializer,
    toc_footer_serializer=_toc_footer_serializer,
    toc_serialization_info=TOCSerializationInfo(
        file=_file_serializer,
        drive=_drive_serializer,
        folder=_folder_serializer,
        name_toc_is_count=False,  # AoE4 is size based, not count based
    ),
)

registry.auto_register(essence_fs_serializer)

__all__ = [
    "FileDefSerializer",
    "MetaBlock",
    "ArchiveHeaderSerializer",
    "essence_fs_serializer",
]
