#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "c2pa.h"
#include <cjson/cJSON.h>

// ---- Memory stream helpers (req by C2PA Rust library) ----

typedef struct {
    uint8_t *buffer;
    size_t length;
    size_t capacity;
    size_t pos;
} MemoryStreamContext;

typedef struct {
    C2paStream *stream;
    MemoryStreamContext *ctx;
} MemoryStream;

// ---- Callbacks ----
/**
 * mem_read: Reads data from a memory stream.
 *
 * @param context   Pointer to the MemoryStreamContext.
 * @param data      Buffer to read data into.
 * @param len       Number of bytes to read.
 *
 * @return Number of bytes actually read, or 0 on EOF.
 */
intptr_t mem_read(struct StreamContext *context, uint8_t *data, intptr_t len) {
    MemoryStreamContext *ctx = (MemoryStreamContext *)context;
    if (ctx->pos >= ctx->length) return 0; // EOF

    intptr_t to_read = (len < (ctx->length - ctx->pos)) ? len : (ctx->length - ctx->pos);
    memcpy(data, ctx->buffer + ctx->pos, to_read);
    ctx->pos += to_read;
    return to_read;
}

/**
 * mem_write: Writes data to a memory stream.
 *
 * @param context   Pointer to the MemoryStreamContext.
 * @param data      Buffer containing data to write.
 * @param len       Number of bytes to write.
 *
 * @return Number of bytes written, or -1 on error.
 */
intptr_t mem_write(struct StreamContext *context, const uint8_t *data, intptr_t len) {
    MemoryStreamContext *ctx = (MemoryStreamContext *)context;

    if (ctx->pos + len > ctx->capacity) {
        size_t new_capacity = (ctx->pos + len) * 2;
        uint8_t *new_buf = realloc(ctx->buffer, new_capacity);
        if (!new_buf) return -1;
        ctx->buffer = new_buf;
        ctx->capacity = new_capacity;
    }

    memcpy(ctx->buffer + ctx->pos, data, len);
    ctx->pos += len;
    if (ctx->pos > ctx->length) ctx->length = ctx->pos;
    return len;
}

/**
 * mem_flush: Flushes the memory stream (no-op).
 *
 * @param context   Pointer to the MemoryStreamContext.
 *
 * @return Always returns 0.
 */
intptr_t mem_flush(struct StreamContext *context) {
    (void)context;
    return 0;
}

/**
 * mem_seek: Moves the position within a memory stream.
 *
 * @param context   Pointer to the MemoryStreamContext.
 * @param offset    Offset to seek to.
 * @param mode      Seek mode (Start, Current, End).
 *
 * @return New position on success, or -1 on error.
 */
intptr_t mem_seek(struct StreamContext *context, intptr_t offset, C2paSeekMode mode) {
    MemoryStreamContext *ctx = (MemoryStreamContext *)context;
    size_t new_pos;

    switch (mode) {
        case Start:   new_pos = offset; break;
        case Current: new_pos = ctx->pos + offset; break;
        case End:     new_pos = ctx->length + offset; break;
        default: return -1;
    }

    if (new_pos > ctx->length) return -1;
    ctx->pos = new_pos;
    return new_pos;
}


/**
 * create_memory_stream: Creates a new memory stream with an initial buffer size.
 *
 * @param initial_size   Initial size of the buffer to allocate.
 *
 * @return Pointer to a newly allocated MemoryStream, or NULL on error.
 *         Caller MUST free it using free_memory_stream().
 */
MemoryStream* create_memory_stream(size_t initial_size) {
    MemoryStreamContext *ctx = calloc(1, sizeof(MemoryStreamContext));
    if (!ctx) return NULL;

    if (initial_size > 0) {
        ctx->buffer = malloc(initial_size);
        if (!ctx->buffer) {
            free(ctx);
            return NULL;
        }
        ctx->capacity = initial_size;
        ctx->length = 0;
        ctx->pos = 0;
    }

    C2paStream *stream = c2pa_create_stream(
        (struct StreamContext *)ctx, mem_read, mem_seek, mem_write, mem_flush
    );

    if (!stream) {
        if (ctx->buffer) free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    MemoryStream *mem_stream = malloc(sizeof(MemoryStream));
    mem_stream->stream = stream;
    mem_stream->ctx = ctx;
    return mem_stream;
}

int write_memory_stream_to_file(MemoryStream *stream, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(stream->ctx->buffer, 1, stream->ctx->length, f);
    fclose(f);
    return 0;
}

/**
 * free_memory_stream: Frees a MemoryStream and its associated resources.
 *
 * @param mem_stream   Pointer to the MemoryStream to free.
 *
 * @return None.
 */
void free_memory_stream(MemoryStream *mem_stream) {
    if (!mem_stream) return;
    c2pa_release_stream(mem_stream->stream);
    free(mem_stream->ctx->buffer);
    free(mem_stream->ctx);
    free(mem_stream);
}

// ------ Utility helpers ------
/**
 * read_file_to_cstring: Reads an entire file into a malloc'd C string.
 *
 * @param path   Path to the file to read.
 *
 * @return Pointer to a newly allocated null-terminated string containing file contents,
 *         or NULL on error. Caller must free the returned string.
 */
char *read_file_to_cstring(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    return buf;
}

/**
 * get_mime_type: Infers the MIME type of a file from its extension.
 *
 * @param filename   Path or name of the file.
 *
 * @return A string representing the MIME type (e.g., "image/png").
 *         Defaults to NULL if unknown.
 */
const char *get_mime_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return NULL;
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".webp") == 0) return "image/webp";
    if (strcmp(ext, ".tiff") == 0 || strcmp(ext, ".tif") == 0) return "image/tiff";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".avif") == 0) return "image/avif";
    if (strcmp(ext, ".dng") == 0) return "image/x-adobe-dng";
    if (strcmp(ext, ".heic") == 0) return "image/heic";
    if (strcmp(ext, ".heif") == 0) return "image/heif";
    return NULL;
}


// ---- Test ----

int main() {

    // define source and destination filenames
    const char *src = "/workspace/tmp/test.png";
    const char* dest = "/workspace/tmp/output.png";

    int error = 0;

    // Read in test cert + key
    char *cert = read_file_to_cstring("/workspace/tmp/es256_certs.pem");
    char *key = read_file_to_cstring("/workspace/tmp/es256_private.key");
    if (!cert || !key) {
        printf("Failed to read cert or key file\n");
        error = 1;
        goto cleanup;
    }

    // create Signer
    C2paSignerInfo info = {
        .alg = "Es256",     // or "Ed25519", etc.
        .sign_cert = cert,  // null-terminated PEM string (cert)
        .private_key = key, // null-terminated PEM string (private key)
        .ta_url = "http://timestamp.digicert.com" //optional
    };

    C2paSigner *signer = c2pa_signer_from_info(&info);
    if (!signer) {
        printf("Failed to create signer: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("Signer created successfully\n");
    }

    // get image mimetype
    const char *mime_type = get_mime_type(src);
    if (!mime_type) {
        printf("Failed to determine MIME type\n");
        error = 1;
        goto cleanup;
    }

    // read in manifest
    const char *manifest = read_file_to_cstring("/workspace/tmp/manifest.json");

    // create Builder
    C2paBuilder *builder = c2pa_builder_from_json(manifest);
    if (!builder) {
        printf("Failed to create builder: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("Builder created successfully\n");
    }

    // Load input image data into source stream
    // Read image file into buffer and get size
    FILE *f = fopen(src, "rb");
    if (!f) {
        printf("Failed to open source image file\n");
        error = 1;
        goto cleanup;
    }
    fseek(f, 0, SEEK_END);
    long img_size = ftell(f);
    rewind(f);

    uint8_t *img_buffer = malloc(img_size);
    if (!img_buffer) { 
        fclose(f);
        printf("Failed to allocate memory for image\n");
        error = 1;
        goto cleanup;
    }
    fread(img_buffer, 1, img_size, f);
    fclose(f);

    // Create memory stream with image size
    MemoryStream *src_stream = create_memory_stream(img_size);
    if (!src_stream) { 
        free(img_buffer);
        printf("Failed to create source stream\n");
        error = 1;
        goto cleanup;
    }

    // Write image data to the stream
    src_stream->stream->writer(src_stream->stream->context, img_buffer, img_size);

    // Reset position to start for reading
    src_stream->stream->seeker(src_stream->stream->context, 0, 0);

    // Free the buffer after writing to stream
    free(img_buffer);

    // Create destination stream
    // get reserve size
    int64_t reserve_size = c2pa_signer_reserve_size(signer);
    // allocate size for image + signature
    size_t dest_size = img_size + reserve_size;
    MemoryStream *dest_stream = create_memory_stream(dest_size);
    if (!dest_stream) {
        printf("Failed to create destination stream\n");
        error = 1;
        goto cleanup;
    }

    // Sign the image
    const unsigned char *manifest_bytes = NULL;
    int size = c2pa_builder_sign(builder, mime_type, src_stream->stream, dest_stream->stream, signer, &manifest_bytes);
    if (size == -1) {
        printf("Signing failed: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("Signing successful\n");
    }

    // Write signed image from dest_stream to disk
    if (write_memory_stream_to_file(dest_stream, dest) != 0) {
        printf("Failed to write output image\n");
        error = 1;
        goto cleanup;
    } else {
        printf("Signed image written to %s\n", dest);
    }

    // Clean up
cleanup:
    if (src_stream) free_memory_stream(src_stream);
    if (dest_stream) free_memory_stream(dest_stream);
    if (manifest_bytes != NULL) c2pa_manifest_bytes_free(manifest_bytes);
    if (builder) c2pa_builder_free(builder);
    if (signer) c2pa_signer_free(signer);
    if (manifest) free(manifest);
    if (cert) free(cert);
    if (key) free(key);
    if (error == 1) return 1;

    return 0;
}

