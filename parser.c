#include <curl/curl.h>
#include <getopt.h>
#include <libusb-1.0/libusb.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define castifcpp(type, x) ((type)(x))
#else
#define castifcpp(type, x) ((x))
#endif

#undef curl_easy_setopt
#define curl_easy_setopt(handle, opt, param)                               \
    _Pragma("clang diagnostic push")                                       \
        _Pragma("clang diagnostic ignored \"-Wdisabled-macro-expansion\"") \
            curl_easy_setopt(handle, opt, param)                           \
                _Pragma("clang diagnostic pop")

typedef struct {
    char* content;
    size_t length;
} response_t;

static char*
get_node(const char* buffer, const char* x, const char* y)
{
    register const char *s, *e;
    if ((s = strstr(buffer, x))) {
        if ((e = strstr(s, y))) {
            register const size_t es = (size_t)(e - s);
            char* o = castifcpp(char*, malloc(es + 1));
            if (!o) {
                fputs("malloc failed.\n", stderr);
                return NULL;
            }
            memcpy(o, s, es);
            o[es] = '\0';
            return o;
        }
    }
    return NULL;
}

static char*
get_n_node(const char* haystack, const char* needle, const size_t size)
{
    register const char* s;
    if ((s = strstr(haystack, needle))) {
        char* o = castifcpp(char*, malloc(size + 1));
        if (!o) {
            fputs("\x1B[31malloc failed.\x1b[0m\n", stderr);
            return NULL;
        }
        memcpy(o, s, size);
        o[size] = '\0';
        return o;
    }
    return NULL;
}

#define get_n_blob(to, haystack, needle, size)                             \
    do {                                                                   \
        char* node = get_n_node(haystack, "<key>" needle "</key>", size);  \
        if (!node) {                                                       \
            fprintf(stderr, "\x1B[31mUnable to find %s\x1b[0m\n", needle); \
            return -1;                                                     \
        }                                                                  \
        strncat(to, node, size);                                           \
        free(node);                                                        \
        haystack += size;                                                  \
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
        curl_easy_setopt(handle, CURLOPT_PROXY, "127.0.0.1:8080");
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
parsend(const char* filename, const char* url, const char* ecid)
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
    char buf[3137] = { '\0' };
    char *manifest, *llb_node, *llb_digest, *llb_partial_digest, *ibec_node, *ibec_digest, *ibec_partialdigest, *ibss_node, *ibss_digest, *ibss_partial_digest;
    strcpy(buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>@APTicket</key><true/><key>@BBTicket</key><true/><key>ApNonce</key><data>EzcTNxM3EzcTNxM3EzcTNxM3Ezc=</data><key>ApECID</key><string>");
    strcat(buf, ecid);
    strcat(buf, "</string><key>ApProductionMode</key><true/>");
    get_n_blob(buf, buffer, "ApBoardID", 41);
    get_n_blob(buf, buffer, "ApChipID", 42);
    get_n_blob(buf, buffer, "ApSecurityDomain", 48);
    if (!(manifest = strstr(buffer, "<key>Manifest</key>"))) {
        fputs("\x1B[31mUnable to find Manifest\x1b[0m\n", stderr);
        return -1;
    }
    get_n_blob(buf, manifest, "AppleLogo", 84);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryCharging0", 91);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryCharging1", 91);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryFull", 86);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryLow0", 86);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryLow1", 86);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "BatteryPlugin", 88);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "DeviceTree", 85);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "KernelCache", 86);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    llb_node = get_node(manifest, "<key>LLB</key>", "<dict><key>Digest");
    if (!llb_node) {
        fputs("\x1B[31mUnable to find LLB\x1b[0m\n", stderr);
        return -1;
    }

    llb_digest = get_node(llb_node, "<key>LLB</key>", "<key>Info");
    if (!llb_digest) {
        free(llb_node);
        fputs("\x1B[31mUnable to find LLB Digest\x1b[0m\n", stderr);
        return -1;
    }
    strncat(buf, llb_digest, 145);
    free(llb_digest);

    llb_partial_digest = get_node(llb_node, "<key>PartialDigest</key>", "</dict><key>OS");
    if (!llb_partial_digest) {
        free(llb_node);
        fputs("\x1B[34mUnable to find LLB PartialDigest (APTicket)\x1b[0m\n", stderr);
    } else {
        free(llb_node);
        strncat(buf, llb_partial_digest, 102);
        free(llb_partial_digest);
    }
    strcat(buf, "</dict>");

    get_n_blob(buf, manifest, "RecoveryMode", 87);
    strcat(buf, "</dict>");
    get_n_blob(buf, manifest, "RestoreDeviceTree", 92);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "RestoreKernelCache", 93);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "RestoreLogo", 86);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "RestoreRamDisk", 89);
    strcat(buf, "<key>Trusted</key><true/></dict>");

    ibec_node = get_node(manifest, "<key>iBEC</key>", "<dict><key>Digest");
    if (!ibec_node) {
        fputs("\x1B[31mUnable to find iBEC\x1b[0m\n", stderr);
        return -1;
    }

    ibec_digest = get_node(ibec_node, "<key>iBEC</key>", "<key>Info");
    if (!ibec_digest) {
        free(ibec_node);
        fputs("\x1B[31mUnable to find iBEC Digest\x1b[0m\n", stderr);
        return -1;
    }
    strncat(buf, ibec_digest, 145);
    free(ibec_digest);

    ibec_partialdigest = get_node(ibec_node, "<key>PartialDigest</key>", "</dict><key>iBSS");
    if (!ibec_partialdigest) {
        free(ibec_node);
        fputs("\x1B[34mUnable to find iBEC PartialDigest (APTicket)\x1b[0m\n", stderr);
    } else {
        free(ibec_node);
        strncat(buf, ibec_partialdigest, 102);
        free(ibec_partialdigest);
    }
    strcat(buf, "</dict>");

    ibss_node = get_node(manifest, "<key>iBSS</key>", "<dict><key>Digest");
    if (!ibss_node) {
        fputs("\x1B[31mUnable to find iBSS\x1b[0m\n", stderr);
        return -1;
    }

    ibss_digest = get_node(ibss_node, "<key>iBSS</key>", "<key>Info");
    if (!ibss_digest) {
        free(ibss_node);
        fputs("\x1B[31mUnable to find iBSS Digest\x1b[0m\n", stderr);
        return -1;
    }
    strncat(buf, ibss_digest, 145);
    free(ibss_digest);

    ibss_partial_digest = get_node(ibss_node, "<key>PartialDigest</key>", "</dict><key>iBoot");
    if (!ibss_partial_digest) {
        free(ibss_node);
        fputs("\x1B[34mUnable to find iBSS PartialDigest (APTicket)\x1b[0m\n", stderr);
    } else {
        free(ibss_node);
        strncat(buf, ibss_partial_digest, 102);
        free(ibss_partial_digest);
    }
    strcat(buf, "</dict>");

    get_n_blob(buf, manifest, "iBoot", 80);
    strcat(buf, "<key>Trusted</key><true/></dict>");
    get_n_blob(buf, manifest, "UniqueBuildID", 65);
    strcat(buf, "</dict></plist>");
    response_t* response = NULL;
    if (!(response = tss_request_send(buf, url))) {
        return -1;
    }
    response->content += 40;

    char* product_version = get_node(buffer, "<key>ProductVersion</key><string>", "</string>");
    if (!product_version) {
        fputs("\x1B[31mUnable to find ProductVersion\x1b[0m\n", stderr);
        return -1;
    }
    product_version += 33;
    printf("\x1B[34mVersion: %s\x1b[0m\n", product_version);
    char out[255];
    snprintf(out, 255, "%s.shsh.plist", product_version);

    FILE* fout = fopen(out, "w");
    if (!fout) {
        return -1;
    }

    if (fwrite(response->content, 1, response->length, fout) != response->length) {
        (void)fclose(fout);
        return -1;
    }
    printf("\x1B[34mBlobs written to %s\x1b[0m\n", out);

    (void)fclose(fout);
    return 0;
}

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

int main(int argc, char* argv[])
{
    int c;
    const char *manifest = NULL, *tss = "https://gs.apple.com/TSS/controller?action=2", *ecid = NULL;

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
            if (strlen(ecid) > 16) {
                return -1;
            }
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
