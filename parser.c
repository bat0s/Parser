#include <curl/curl.h>
#include <getopt.h>
#if 0
#include <libusb-1.0/libusb.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define castifcpp(type, x) ((type)(x))
#else
#define castifcpp(type, x) ((x))
#endif

typedef struct {
    char* content;
    size_t length;
} response_t;

#define get_blob(to, haystack, needle, needlend, size)                     \
    do {                                                                   \
        register char *start, *end;                                        \
        if ((start = strstr(haystack, "<key>" needle "</key>")) == NULL) { \
            free(to);                                                      \
            fprintf(stderr, "\x1B[31mUnable to find %s\x1b[0m\n", needle); \
            return -1;                                                     \
        }                                                                  \
        if ((end = strstr(start, needlend)) == NULL) {                     \
            free(to);                                                      \
            return -1;                                                     \
        }                                                                  \
        strncat(to, start, (size_t)(end - start) + size);                  \
        haystack = end + size;                                             \
    } while (0)

#define get_partialdigest(to, haystack, needle, size)                 \
    do {                                                              \
        register char *start, *end;                                   \
        if ((start = strstr(haystack, "<key>PartialDigest</key>"))) { \
            if ((end = strstr(start, needle))) {                      \
                strncat(to, start, (size_t)(end - start) + size);     \
                haystack = end + size;                                \
            } else {                                                  \
                strcat(to, "<key>Trusted</key><true/></dict>");       \
            }                                                         \
        }                                                             \
    } while (0)

static inline __attribute__((always_inline)) void
strip(char* s)
{
    register char* p = s;
    do {
        if (*s != '\t' && *s != '\n') {
            *p++ = *s++;
        } else {
            ++s;
        }
    } while (*s != '\0');
    *p = '\0';
}

static size_t
tss_writecb(char* data, size_t size, size_t nmemb, response_t* response)
{
    register size_t total = size * nmemb;

    if (total != 0) {
        response->content = castifcpp(char*, realloc(response->content, response->length + total + 1));
        memcpy(response->content + response->length, data, total);
        response->content[response->length + total] = '\0';
        response->length += total;
    }

    return total;
}

static response_t*
tss_request_send(const char* request, const char* url)
{

    register int i = 15;
    response_t* response = NULL;

    while (i--) {
        response = NULL;
        CURL* handle = curl_easy_init();
        if (!handle) {
            break;
        }
        struct curl_slist* header = NULL;
        header = curl_slist_append(header, "Cache-Control: no-cache");
        header = curl_slist_append(header, "Content-type: text/xml; charset=\"utf-8\"");
        header = curl_slist_append(header, "Expect:");

        response = castifcpp(response_t*, malloc(sizeof(response_t)));
        if (!response) {
            fprintf(stderr, "\x1B[31mUnable to allocate sufficent memory\x1b[0m\n");
            break;
        }
        response->length = 0;
        response->content = castifcpp(char*, malloc(1));
        response->content[0] = '\0';

        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &tss_writecb);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request);
        curl_easy_setopt(handle, CURLOPT_USERAGENT, "Parser/1.0");
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(request));
        curl_easy_setopt(handle, CURLOPT_URL, url);
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, 20L);
        curl_easy_perform(handle);
        curl_slist_free_all(header);
        curl_easy_cleanup(handle);

        if (strstr(response->content, "MESSAGE=SUCCESS")) {
            return response;
        }
        if (strstr(response->content, "MESSAGE=This device isn't eligible for the requested build.")) {
            fputs("\x1B[31mThis device isn't eligible for the requested build.\x1b[0m\n", stderr);
            return NULL;
        }
        printf("\x1B[34mAttempt %d, response: (%s)\x1b[0m\n", i, response->content);
    }
    return NULL;
}

static int
parsend(const char* filename, const char* url, char* ecid)
{
    FILE* file = fopen(filename, "r");

    if (!file) {
        fprintf(stderr, "\x1B[31mUnable to find (%s)\x1b[0m\n", filename);
        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        (void)fclose(file);
        fputs("\x1B[31mfseek failed.\x1b[0m\n", stderr);
        return -1;
    }

    size_t len = (size_t)ftell(file);

    if (len <= 0) {
        (void)fclose(file);
        fputs("\x1B[31mftell failed.\x1b[0m\n", stderr);
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        (void)fclose(file);
        fputs("\x1B[31mfseek failed.\x1b[0m\n", stderr);
        return -1;
    }

    char* buffer = castifcpp(char*, malloc(len));

    if (!buffer) {
        (void)fclose(file);
        fputs("\x1B[31mmalloc failed.\x1b[0m\n", stderr);
        return -1;
    }

    if (fread(buffer, 1, len, file) != len) {
        free(buffer);
        (void)fclose(file);
        fputs("\x1B[31mfread failed.\x1b[0m\n", stderr);
        return -1;
    }

    (void)fclose(file);

    strip(buffer);
    buffer += 206;
    char* buf = castifcpp(char*, malloc(strlen(buffer) + strlen(ecid) + 1));
    strcpy(buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>@APTicket</key><true/><key>@BBTicket</key><true/><key>ApNonce</key><data>EzcTNxM3EzcTNxM3EzcTNxM3Ezc=</data><key>ApECID</key><string>");
    strcat(buf, ecid);
    strcat(buf, "</string><key>ApProductionMode</key><true/>");
    get_blob(buf, buffer, "ApBoardID", "</string>", 9);
    get_blob(buf, buffer, "ApChipID", "</string>", 9);
    get_blob(buf, buffer, "ApSecurityDomain", "</string>", 9);

    register char *s, *e;
    if (!(s = strstr(buffer, "<key>Manifest</key>"))) {
        free(buf);
        return -1;
    }
    s += 25;
    e = strstr(s, "<key>ApBoardID</key>");
    if (e) {
        s[e - s] = '\0';
    }

    get_blob(buf, s, "AppleLogo", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryCharging0", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryCharging1", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryFull", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryLow0", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryLow1", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "BatteryPlugin", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "DeviceTree", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "KernelCache", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "LLB", "</data>", 7);
    get_partialdigest(buf, s, "</dict><key>OS", 7);
    get_blob(buf, s, "RecoveryMode", "</data>", 7);
    strcat(buf, "</dict>");
    get_blob(buf, s, "RestoreDeviceTree", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "RestoreKernelCache", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "RestoreLogo", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "RestoreRamDisk", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "iBEC", "</data>", 7);
    get_partialdigest(buf, s, "</dict><key>iBSS", 7);
    get_blob(buf, s, "iBSS", "</data>", 7);
    get_partialdigest(buf, s, "</dict><key>iBoot", 7);
    get_blob(buf, s, "iBoot", "</data>", 7);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_blob(buf, s, "UniqueBuildID", "</dict>", 7);
    strcat(buf, "</plist>");

    response_t* response = NULL;
    if (!(response = tss_request_send(buf, url))) {
        free(buf);
        return -1;
    }
    free(buf);
    response->content += 40;

    strcat(ecid, ".shsh.plist");

    FILE* fout = fopen(ecid, "w");
    if (!fout) {
        free(response);
        return -1;
    }

    if (fwrite(response->content, 1, response->length, fout) != response->length) {
        free(response);
        (void)fclose(fout);
        return -1;
    }
    free(response);

    printf("\x1B[34mBlobs written to %s\x1b[0m\n", ecid);

    (void)fclose(fout);
    return 0;
}

#if 0
static __attribute((__unused__)) char*
get_nonce(const char* ecid)
{
    struct libusb_device **devs, *device;
    struct libusb_device_handle* handle = NULL;
    ssize_t i = 0, deviceCount;

    libusb_init(NULL);

    if ((deviceCount = libusb_get_device_list(NULL, &devs)) < 0) {
        libusb_exit(NULL);
        return NULL;
    }

    while ((device = devs[i++]) != NULL) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(device, &desc) < LIBUSB_SUCCESS) {
            goto error;
        }

        printf("\x1B[34mVendor ID : (0x%04X) Product ID : (0x%04X)\x1b[0m\n", desc.idVendor,
            desc.idProduct);
        if (desc.idVendor == 0x05AC && (desc.idProduct == 0x1281 || desc.idProduct == 0x1227 || desc.idProduct == 0x1282 || desc.idProduct == 0x1283)) {
            if (libusb_open(device, &handle) < LIBUSB_SUCCESS) {
                goto error;
            }
        }

        char serial[255];
        if (libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, (unsigned char*)serial, 255) < LIBUSB_SUCCESS) {
            goto error;
        }

        char* ptr = NULL;
        if (ecid != NULL && !(ptr = strstr(serial, ecid))) {
            goto error;
        }

        static char buf[255];
        if (libusb_get_string_descriptor_ascii(handle, 1, (unsigned char*)buf, 255) < LIBUSB_SUCCESS) {
            goto error;
        }

        libusb_free_device_list(devs, 1);
        libusb_close(handle);
        libusb_exit(NULL);
        buf[41] = '\0';
        return &buf[6];
    }
    return NULL;
error:
    libusb_free_device_list(devs, 1);
    libusb_close(handle);
    libusb_exit(NULL);
    return NULL;
}
#endif

int main(int argc, char* argv[])
{
    int c;
    char *manifest = NULL, *tss = "https://gs.apple.com/TSS/controller?action=2", *ecid = NULL;

    if (argc < 3) {
        fprintf(stderr, "\x1B[34m%s -b <BuildManifest.plist> -t [TSS Server] -e [ECID]\x1b[0m\n", argv[0]);
        return -1;
    }

    while ((c = getopt(argc, argv, "b:t:e:")) != EOF)
        switch (c) {
        case 'b':
            manifest = optarg;
            break;
        case 't':
            tss = optarg;
            break;
        case 'e':
            ecid = optarg;
            break;
        case '?':
            return -1;
        default:
            return -1;
        }

    if (!manifest || !ecid) {
        fprintf(stderr, "\x1B[34m%s <BuildManifest.plist> [TSS Server] [ECID]\x1b[0m\n", argv[0]);
        return -1;
    }

    if (parsend(manifest, tss, ecid) != 0) {
        fputs("\x1B[31mUnable to parse and send\x1b[0m\n", stderr);
        return -1;
    }
}
