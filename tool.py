#!/usr/bin/env python3
"""
File System Analyzer Tool
A command-line tool that analyzes and reports on file system structure and usage.
"""

import os
import sys
import argparse

# check Python version requirement (because match statements are used)
if sys.version_info < (3, 10):
    print("Error: Python 3.10 or higher is required (match statements are used)")
    print(f"Current version: {sys.version}")
    sys.exit(1)

import stat
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Set
from enum import Enum

class FileCategory(Enum):
    """File categories for classification"""
    TEXT = 'text'
    IMAGE = 'image'
    EXECUTABLE = 'executable'
    ARCHIVE = 'archive'
    DOCUMENT = 'document'
    VIDEO = 'video'
    AUDIO = 'audio'
    CONFIG = 'config'
    APPLICATION = 'application'
    OTHER = 'other'

@dataclass
class FileInfo:
    """Information about a single file"""
    path: Path
    size: int
    category: FileCategory
    permissions_issue: Optional[str] = None

class FileSystemAnalyzer:
    """Analyzes file system structure and reports statistics"""
    
    # File type mappings
    EXTENSION_MAP: Dict[str, FileCategory] = {
        # text files
        '.txt': FileCategory.TEXT, '.md': FileCategory.TEXT, '.py': FileCategory.TEXT,
        '.js': FileCategory.TEXT, '.html': FileCategory.TEXT, '.css': FileCategory.TEXT,
        '.json': FileCategory.TEXT, '.xml': FileCategory.TEXT, '.csv': FileCategory.TEXT,
        '.log': FileCategory.TEXT,
        
        # images
        '.jpg': FileCategory.IMAGE, '.jpeg': FileCategory.IMAGE, '.png': FileCategory.IMAGE,
        '.gif': FileCategory.IMAGE, '.bmp': FileCategory.IMAGE, '.svg': FileCategory.IMAGE,
        '.ico': FileCategory.IMAGE, '.webp': FileCategory.IMAGE,
        
        # executables
        '.exe': FileCategory.EXECUTABLE, '.bin': FileCategory.EXECUTABLE,
        '.sh': FileCategory.EXECUTABLE, '.bat': FileCategory.EXECUTABLE,
        '.com': FileCategory.EXECUTABLE, '.msi': FileCategory.EXECUTABLE,
        
        # archives
        '.zip': FileCategory.ARCHIVE, '.tar': FileCategory.ARCHIVE, '.gz': FileCategory.ARCHIVE,
        '.rar': FileCategory.ARCHIVE, '.7z': FileCategory.ARCHIVE, '.bz2': FileCategory.ARCHIVE,
        '.xz': FileCategory.ARCHIVE,
        
        # documents
        '.pdf': FileCategory.DOCUMENT, '.doc': FileCategory.DOCUMENT, '.docx': FileCategory.DOCUMENT,
        '.xls': FileCategory.DOCUMENT, '.xlsx': FileCategory.DOCUMENT, '.ppt': FileCategory.DOCUMENT,
        '.pptx': FileCategory.DOCUMENT,
        
        # video
        '.mp4': FileCategory.VIDEO, '.avi': FileCategory.VIDEO, '.mkv': FileCategory.VIDEO,
        '.mov': FileCategory.VIDEO, '.wmv': FileCategory.VIDEO, '.flv': FileCategory.VIDEO,
        '.webm': FileCategory.VIDEO,
        
        # audio
        '.mp3': FileCategory.AUDIO, '.wav': FileCategory.AUDIO, '.flac': FileCategory.AUDIO,
        '.aac': FileCategory.AUDIO, '.ogg': FileCategory.AUDIO, '.wma': FileCategory.AUDIO,
        
        # config
        '.conf': FileCategory.CONFIG, '.cfg': FileCategory.CONFIG, '.ini': FileCategory.CONFIG,
        '.yaml': FileCategory.CONFIG, '.yml': FileCategory.CONFIG, '.toml': FileCategory.CONFIG,
    }
    
    # file signatures
    FILE_SIGNATURES: Dict[bytes, FileCategory] = {
        # images
        b'\xFF\xD8\xFF': FileCategory.IMAGE,  # JPEG
        b'\x89PNG\r\n\x1a\n': FileCategory.IMAGE,  # PNG
        b'GIF87a': FileCategory.IMAGE,  # GIF87a
        b'GIF89a': FileCategory.IMAGE,  # GIF89a
        b'BM': FileCategory.IMAGE,  # BMP
        b'\x00\x00\x01\x00': FileCategory.IMAGE,  # ICO
        
        # archives
        b'PK\x03\x04': FileCategory.ARCHIVE,  # ZIP
        b'PK\x05\x06': FileCategory.ARCHIVE,  # ZIP (empty)
        b'PK\x07\x08': FileCategory.ARCHIVE,  # ZIP (spanned)
        b'\x1f\x8b': FileCategory.ARCHIVE,  # GZIP
        b'\x42\x5a\x68': FileCategory.ARCHIVE,  # BZIP2
        
        # documents
        b'%PDF': FileCategory.DOCUMENT,  # PDF
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': FileCategory.DOCUMENT,  # MS Office
        
        # executables
        b'MZ': FileCategory.EXECUTABLE,  # PE/DOS executable
        b'\x7f\x45\x4c\x46': FileCategory.EXECUTABLE,  # ELF
        b'\xfe\xed\xfa\xce': FileCategory.EXECUTABLE,  # Mach-O 32-bit
        b'\xfe\xed\xfa\xcf': FileCategory.EXECUTABLE,  # Mach-O 64-bit
        b'\xca\xfe\xba\xbe': FileCategory.EXECUTABLE,  # Mach-O universal
        b'\xce\xfa\xed\xfe': FileCategory.EXECUTABLE,  # Mach-O 32-bit reverse
        b'\xcf\xfa\xed\xfe': FileCategory.EXECUTABLE,  # Mach-O 64-bit reverse
        
        # audio/video
        b'\x49\x44\x33': FileCategory.AUDIO,  # MP3 ID3v2
        b'\xff\xfb': FileCategory.AUDIO,  # MP3
        b'\x4f\x67\x67\x53': FileCategory.AUDIO,  # OGG
        b'RIFF': FileCategory.AUDIO,  # WAV (needs additional check)
        b'fLaC': FileCategory.AUDIO,  # FLAC
    }
    
    # extensions that should not be executable
    SUSPICIOUS_EXECUTABLE_EXTENSIONS: Set[str] = {'.txt', '.log', '.conf', '.cfg', '.ini'}
    
    def __init__(self, directory: str, size_threshold: int = 1024*1024, use_signatures: bool = True, max_large_files: int = 10):
        self.directory = Path(directory)
        self.size_threshold = size_threshold
        self.use_signatures = use_signatures
        self.max_large_files = max_large_files
        
        # results storage
        self.files_by_category: Dict[FileCategory, List[FileInfo]] = defaultdict(list)
        self.category_sizes: Dict[FileCategory, int] = defaultdict(int)
        self.large_files: List[FileInfo] = []
        self.permission_issues: List[FileInfo] = []
        self.total_files = 0
        self.total_size = 0
        self.errors: List[Tuple[Path, str]] = []
    
    def detect_file_signature(self, file_path: Path) -> Optional[FileCategory]:
        """Detect file type using magic bytes/file signatures"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
                
                if not header:
                    return None
                
                # check signatures first
                for signature, category in self.FILE_SIGNATURES.items():
                    if header.startswith(signature):
                        # special case for RIFF files
                        if signature == b'RIFF' and len(header) >= 12:
                            match header[8:12]:
                                case b'WAVE':
                                    return FileCategory.AUDIO
                                case b'AVI ':
                                    return FileCategory.VIDEO
                        return category
                
                # check for MP4 variants (ftyp box at offset 4)
                if len(header) >= 12 and header[4:8] == b'ftyp':
                    match header[8:12]:
                        case b'mp41' | b'mp42' | b'isom' | b'f4v ' | b'F4V ':
                            return FileCategory.VIDEO
                        case b'M4V ':
                            return FileCategory.VIDEO
                        case b'M4A ':
                            return FileCategory.AUDIO
                
                # check for text files
                if self._is_text_content(header):
                    return FileCategory.TEXT
                    
        except (OSError, PermissionError):
            pass
        
        return None
    
    def _is_text_content(self, data: bytes) -> bool:
        """Check if content appears to be text"""
        if not data:
            return False
            
        # allow printable ASCII, common whitespace, and UTF-8 BOMs
        text_chars = set(range(32, 127)) | {9, 10, 13}  # tab, newline, carriage return
        
        # check for UTF-8 BOM
        match data[:3]:
            case b'\xef\xbb\xbf':  # UTF-8 BOM
                return True
            case b'\xff\xfe' | b'\xfe\xff':  # UTF-16 BOMs
                return True
            
        # check if mostly printable characters
        printable_count = sum(1 for byte in data if byte in text_chars)
        return printable_count / len(data) > 0.85
    
    def get_file_category(self, file_path: Path) -> FileCategory:
        """Categorize file using signatures, then extension"""
        # try file signature first
        if self.use_signatures:
            signature_category = self.detect_file_signature(file_path)
            if signature_category:
                return signature_category
        
        # fall back to extension
        suffix = file_path.suffix.lower()
        return self.EXTENSION_MAP.get(suffix, FileCategory.OTHER)
    
    def check_permissions(self, file_path: Path, file_stat: os.stat_result) -> Optional[str]:
        """Check for unusual file permissions"""
        mode = file_stat.st_mode
        issues = []
        
        # world-writable files
        if mode & stat.S_IWOTH:
            issues.append("world-writable")
        
        # SUID/SGID files
        if mode & stat.S_ISUID:
            issues.append("SUID")
        if mode & stat.S_ISGID:
            issues.append("SGID")
        
        # executable text files
        if (mode & stat.S_IXUSR) and file_path.suffix.lower() in self.SUSPICIOUS_EXECUTABLE_EXTENSIONS:
            issues.append("suspicious-executable")
        
        return ", ".join(issues) if issues else None
    
    def analyze_file(self, file_path: Path) -> Optional[FileInfo]:
        """Analyze a single file"""
        try:
            file_stat = file_path.stat()
            
            # skip non-regular files
            if not stat.S_ISREG(file_stat.st_mode):
                return None
                
            file_size = file_stat.st_size
            category = self.get_file_category(file_path)
            permissions_issue = self.check_permissions(file_path, file_stat)
            
            return FileInfo(
                path=file_path,
                size=file_size,
                category=category,
                permissions_issue=permissions_issue
            )
            
        except (OSError, PermissionError) as e:
            self.errors.append((file_path, str(e)))
            return None
    
    def analyze_directory(self) -> None:
        """Main analysis function"""
        if not self.directory.exists():
            raise FileNotFoundError(f"Directory '{self.directory}' does not exist")
        
        if not self.directory.is_dir():
            raise NotADirectoryError(f"'{self.directory}' is not a directory")
        
        print(f"Analyzing directory: {self.directory}")
        print("=" * 50)
        
        # use os.walk for efficiency
        for root, dirs, files in os.walk(self.directory):
            root_path = Path(root)
            
            # filter out inaccessible directories
            dirs[:] = [d for d in dirs if self._can_access(root_path / d)]
            
            for file_name in files:
                file_path = root_path / file_name
                file_info = self.analyze_file(file_path)
                
                if file_info:
                    # update counters
                    self.total_files += 1
                    self.total_size += file_info.size
                    
                    # categorize
                    self.files_by_category[file_info.category].append(file_info)
                    self.category_sizes[file_info.category] += file_info.size
                    
                    # check for large files
                    if file_info.size > self.size_threshold:
                        self.large_files.append(file_info)
                    
                    # check for permission issues
                    if file_info.permissions_issue:
                        self.permission_issues.append(file_info)
    
    def _can_access(self, path: Path) -> bool:
        """Check if directory can be accessed"""
        try:
            path.stat()
            return True
        except (OSError, PermissionError):
            return False
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0 B"
            
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} EB"
    
    def generate_report(self) -> None:
        """Generate and display the analysis report"""
        print("\n" + "=" * 50)
        print("FILE SYSTEM ANALYSIS REPORT")
        print("=" * 50)
        
        print(f"\nTotal files analyzed: {self.total_files:,}")
        print(f"Total size: {self.format_size(self.total_size)}")
        
        # type categorization
        print("\nFILE TYPE CATEGORIES:")
        print("-" * 30)
        
        # sort categories by total size (descending)
        sorted_categories = sorted(
            self.files_by_category.items(),
            key=lambda x: self.category_sizes[x[0]],
            reverse=True
        )
        
        for category, files in sorted_categories:
            count = len(files)
            size = self.category_sizes[category]
            percentage = (size / self.total_size * 100) if self.total_size > 0 else 0
            print(f"{category.value.capitalize():<12}: {count:>6} files, "
                  f"{self.format_size(size):>10} ({percentage:>5.1f}%)")
        
        # large files report
        print(f"\nLARGE FILES (> {self.format_size(self.size_threshold)}):")
        print("-" * 50)
        if self.large_files:
            # sort by size, largest first
            self.large_files.sort(key=lambda x: x.size, reverse=True)
            for file_info in self.large_files[:self.max_large_files]:
                rel_path = file_info.path.relative_to(self.directory)
                print(f"{self.format_size(file_info.size):>10}  {rel_path}")
            
            if len(self.large_files) > self.max_large_files:
                print(f"\n... and {len(self.large_files) - self.max_large_files} more large files")
        else:
            print("No large files found")
        
        # permission issues report
        print("\nPERMISSION ISSUES:")
        print("-" * 30)
        if self.permission_issues:
            # group by issue type
            issues_by_type = defaultdict(list)
            for file_info in self.permission_issues:
                if file_info.permissions_issue:
                    issues_by_type[file_info.permissions_issue].append(file_info)
            
            for issue_type, files in sorted(issues_by_type.items()):
                print(f"\n{issue_type}:")
                for file_info in files[:5]:
                    rel_path = file_info.path.relative_to(self.directory)
                    print(f"  {rel_path}")
                if len(files) > 5:
                    print(f"  ... and {len(files) - 5} more")
        else:
            print("No files with unusual permissions found")
        
        # errors report
        if self.errors:
            print("\nERRORS ENCOUNTERED:")
            print("-" * 30)
            for path, error in self.errors[:10]:
                rel_path = path.relative_to(self.directory)
                print(f"  {rel_path}: {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more errors")

def parse_size(size_str: str) -> int:
    """Parse human-readable size string to bytes"""
    size_str = size_str.strip().upper()
    multipliers = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024**2,
        'MB': 1024**2,
        'G': 1024**3,
        'GB': 1024**3,
        'T': 1024**4,
        'TB': 1024**4,
    }
    
    # extract number and unit
    for suffix, multiplier in multipliers.items():
        if size_str.endswith(suffix):
            try:
                number = float(size_str[:-len(suffix)])
                return int(number * multiplier)
            except ValueError:
                break
    
    # try parsing as plain number
    try:
        return int(size_str)
    except ValueError:
        raise ValueError(f"Invalid size format: '{size_str}'")

def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Analyze file system structure and usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /home/user                      # Analyze /home/user directory
  %(prog)s /var/log --size-threshold 10M   # Find files larger than 10MB
  %(prog)s . -s 1G                         # Analyze current directory, 1GB threshold
  %(prog)s /data --no-signatures           # Fast scan without file signature detection
  %(prog)s . --max-large-files 25          # Show top 25 large files instead of 10
        """
    )
    
    parser.add_argument(
        'directory',
        help='Directory to analyze'
    )
    
    parser.add_argument(
        '-s', '--size-threshold',
        default='1M',
        help='Size threshold for large files (e.g., 1M, 10M, 1G). Default: 1M'
    )
    
    parser.add_argument(
        '--no-signatures',
        action='store_true',
        help='Disable file signature detection for faster processing (extension-based only)'
    )
    
    parser.add_argument(
        '--max-large-files',
        type=int,
        default=10,
        help='Maximum number of large files to display in report. Default: 10'
    )
    
    args = parser.parse_args()
    
    # parse size threshold
    try:
        size_threshold = parse_size(args.size_threshold)
    except ValueError as e:
        print(f"Error: {e}")
        print("Use format like: 1M, 10MB, 1G, 500K, etc.")
        sys.exit(1)
    
    try:
        analyzer = FileSystemAnalyzer(
            args.directory, 
            size_threshold, 
            use_signatures=not args.no_signatures,
            max_large_files=args.max_large_files
        )
        analyzer.analyze_directory()
        analyzer.generate_report()
        
    except (FileNotFoundError, NotADirectoryError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()