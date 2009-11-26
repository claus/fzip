package deng.utils
{
	import flash.utils.ByteArray;
	
	public class ChecksumUtil
	{
		/**
		 * @private
		 */		
		private static var crcTable:Array = makeCRCTable();
		
		/**
		 * @private
		 */		
		private static function makeCRCTable():Array {
			var table:Array = [];
			var i:uint;
			var j:uint;
			var c:uint;
			for (i = 0; i < 256; i++) {
				c = i;
				for (j = 0; j < 8; j++) {
					if (c & 1) {
						c = 0xEDB88320 ^ (c >>> 1);
					} else {
						c >>>= 1;
					}
				}
				table.push(c);
			}
			return table;
		}
		
		/**
		 * Calculates a CRC-32 checksum over a ByteArray
		 * 
		 * @see http://www.w3.org/TR/PNG/#D-CRCAppendix
		 * 
		 * @param data 
		 * @param len
		 * @param start
		 * @return CRC-32 checksum
		 */		
		public static function CRC32(data:ByteArray, start:uint = 0, len:uint = 0):uint {
			if (start >= data.length) { start = data.length; }
			if (len == 0) { len = data.length - start; }
			if (len + start > data.length) { len = data.length - start; }
			var i:uint;
			var c:uint = 0xffffffff;
			for (i = start; i < len; i++) {
				c = uint(crcTable[(c ^ data[i]) & 0xff]) ^ (c >>> 8);
			}
			return (c ^ 0xffffffff);
		}
		
		/**
		 * Calculates an Adler-32 checksum over a ByteArray
		 * 
		 * @see http://en.wikipedia.org/wiki/Adler-32#Example_implementation
		 * 
		 * @param data 
		 * @param len
		 * @param start
		 * @return Adler-32 checksum
		 */		
		public static function Adler32(data:ByteArray, start:uint = 0, len:uint = 0):uint {
			if (start >= data.length) { start = data.length; }
			if (len == 0) { len = data.length - start; }
			if (len + start > data.length) { len = data.length - start; }
			var i:uint = start;
			var a:uint = 1;
			var b:uint = 0;
			while (i < (start + len)) {
				a = (a + data[i]) % 65521;
				b = (a + b) % 65521;
				i++;
			}
			return (b << 16) | a;
		}
	}
}
