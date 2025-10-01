#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include "c2pa.h"
#include <cjson/cJSON.h>

typedef struct {
    uint8_t *buffer;
    size_t length;
    size_t capacity;
    size_t pos;
} MemoryStreamContext;

// ---- Callbacks ----
// Read from memory stream
intptr_t mem_read(struct StreamContext *context, uint8_t *data, intptr_t len) {
    MemoryStreamContext *ctx = (MemoryStreamContext *)context;
    if (ctx->pos >= ctx->length) return 0; // EOF

    intptr_t to_read = (len < (ctx->length - ctx->pos)) ? len : (ctx->length - ctx->pos);
    memcpy(data, ctx->buffer + ctx->pos, to_read);
    ctx->pos += to_read;
    return to_read;
}

// Write to memory stream
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

// Flush (no-op)
intptr_t mem_flush(struct StreamContext *context) {
    (void)context;
    return 0;
}

// Seek
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


typedef struct {
    C2paStream *stream;
    MemoryStreamContext *ctx;
} OwnedMemoryStream;

OwnedMemoryStream* create_owned_memory_stream() {
    MemoryStreamContext *ctx = calloc(1, sizeof(MemoryStreamContext));
    if (!ctx) return NULL;

    C2paStream *stream = c2pa_create_stream(
        (struct StreamContext *)ctx, mem_read, mem_seek, mem_write, mem_flush
    );


    if (!stream) {
        free(ctx);
        return NULL;
    }

    OwnedMemoryStream *owned = malloc(sizeof(OwnedMemoryStream));
    owned->stream = stream;
    owned->ctx = ctx;
    return owned;
}

void free_owned_memory_stream(OwnedMemoryStream *owned) {
    if (!owned) return;
    c2pa_release_stream(owned->stream);
    free(owned->ctx->buffer);
    free(owned->ctx);
    free(owned);
}

// Utility: read an entire file into a malloc’d C string
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

OwnedMemoryStream* create_owned_memory_stream_from_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    MemoryStreamContext *ctx = calloc(1, sizeof(MemoryStreamContext));
    ctx->buffer = malloc(len);
    if (!ctx->buffer) {
        fclose(f);
        free(ctx);
        return NULL;
    }
    fread(ctx->buffer, 1, len, f);
    fclose(f);

    ctx->length = len;
    ctx->capacity = len;
    ctx->pos = 0;

    C2paStream *stream = c2pa_create_stream(
        (struct StreamContext *)ctx, mem_read, mem_seek, mem_write, mem_flush
    );

    OwnedMemoryStream *owned = malloc(sizeof(OwnedMemoryStream));
    owned->stream = stream;
    owned->ctx = ctx;
    return owned;
}

int write_owned_memory_stream_to_file(OwnedMemoryStream *owned, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(owned->ctx->buffer, 1, owned->ctx->length, f);
    fclose(f);
    return 0;
}

bool check_for_provenance(const char *recipe, bool *detailed) {
    bool prov_check = false;
    if (detailed) *detailed = false;

    cJSON *recipe_json = cJSON_Parse(recipe);
    if (recipe_json) {
        cJSON *provenance = cJSON_GetObjectItem(recipe_json, "provenance");
        if (provenance && cJSON_IsObject(provenance)) {
            prov_check = true;
            if (detailed) {
                cJSON *detailed_field = cJSON_GetObjectItem(provenance, "detailed");
                if (detailed_field && cJSON_IsTrue(detailed_field)) {
                    *detailed = true;
                }
            }
        }
        cJSON_Delete(recipe_json);
    }
    return prov_check;
}

// ---- Test harness ----

int main() {

    int error = 0;

    char *recipe = read_file_to_cstring("/workspace/tmp/prov-bbc-1024x576.json");
    if (!recipe) {
        printf("Failed to read recipe file\n");
        error = 1;
        goto cleanup;
    }
    bool detailed;
    bool provenance = check_for_provenance(recipe, &detailed);
    printf("Provenance in recipe: %s, detailed: %s\n", provenance ? "yes" : "no", detailed ? "yes" : "no");

    // Read test cert + key
    char *cert = read_file_to_cstring("/workspace/tmp/es256_certs.pem");
    char *key = read_file_to_cstring("/workspace/tmp/es256_private.key");
    if (!cert || !key) {
        printf("Failed to read cert or key file\n");
        error = 1;
        goto cleanup;
    }

    C2paSignerInfo info = {
        .alg = "Es256",     // or "Ed25519", etc.
        .sign_cert = cert,  // null-terminated PEM string (cert)
        .private_key = key, // null-terminated PEM string (private key)
        .ta_url = "http://timestamp.digicert.com"
    };

    C2paSigner *signer = c2pa_signer_from_info(&info);
    if (!signer) {
        printf("Failed to create signer: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("Signer created successfully\n");
    }

    const char *manifest = read_file_to_cstring("/workspace/tmp/manifest.json");

    C2paBuilder *builder = c2pa_builder_from_json(manifest);
    if (!builder) {
        printf("Failed to create builder: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("Builder created successfully\n");
    }

    const char *src = "/workspace/tmp/test.png";
    const char* dest = "/workspace/tmp/output.png";

    // char *res = c2pa_sign_file(src, dest, empty_manifest, &info, NULL);
    // if (!res) {
    //     printf("Signing failed: %s\n", c2pa_error());
    //     error = 1;
    //     goto cleanup;
    // } else {
    //     printf("Image signed successfully!\n");
    // }

    const char *png_mime_type = "image/png";
    const char* dest_2 = "/workspace/tmp/output_2.png";
    const unsigned char *manifest_bytes = NULL;

    // Load input PNG into source stream
    OwnedMemoryStream *src_stream = create_owned_memory_stream_from_file(src);
    if (!src_stream) {
        printf("Failed to create source stream\n");
        error = 1;
        goto cleanup;
    }

    // Create empty destination stream
    OwnedMemoryStream *dest_stream = create_owned_memory_stream();
    if (!dest_stream) {
        printf("Failed to create destination stream\n");
        error = 1;
        goto cleanup;
    }

    printf("builder=%p, src_stream=%p, dest_stream=%p, signer=%p\n", builder, src_stream, dest_stream, signer);

    int size = c2pa_builder_sign(builder, png_mime_type, src_stream->stream, dest_stream->stream, signer, &manifest_bytes);
    if (size == -1) {
        printf("c2pa_builder_sign failed: %s\n", c2pa_error());
        error = 1;
        goto cleanup;
    } else {
        printf("c2pa_builder_sign succeeded, size: %d\n", size);
    }

    // Write signed PNG from dest_stream to disk
    if (write_owned_memory_stream_to_file(dest_stream, dest_2) != 0) {
        printf("Failed to write output PNG\n");
        error = 1;
        goto cleanup;
    } else {
        printf("Signed PNG written to %s\n", dest_2);
    }

    // Clean up
cleanup:
    if (src_stream) free_owned_memory_stream(src_stream);
    if (dest_stream) free_owned_memory_stream(dest_stream);
    if (manifest_bytes != NULL) c2pa_manifest_bytes_free(manifest_bytes);
    //if (res) c2pa_string_free(res);
    if (builder) c2pa_builder_free(builder);
    if (signer) c2pa_signer_free(signer);
    if (cert) free(cert);
    if (key) free(key);
    if (recipe) free(recipe);
    if (error == 1) return 1;

    return 0;
}

