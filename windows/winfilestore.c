/*
 * file_store.c: Windows-specific implementation of the interface
 * defined in storage.h.
 */

/*
 * Based on Aljex OSC 7.5.5.0000 patches to putty 0.69
 * which was itself based on portaPuTTY_0.60 from Socialist Sushi
 *
 * This stores sessions as files with a ".at" extension in the public documents
 * folder.
*/

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "putty.h"
#include "storage.h"
#include "tree234.h"
#include "dirent.h"

#include <shlobj.h>

#include <shlwapi.h>

#ifdef _MAX_PATH
#define FNLEN _MAX_PATH
#else
#define FNLEN 1024 /* XXX */
#endif

#ifndef S_ISREG
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#endif

enum {
    INDEX_DIR, INDEX_HOSTKEYS, INDEX_HOSTKEYS_TMP, INDEX_RANDSEED,
    INDEX_SESSIONDIR, INDEX_SESSION,
};

static const char hex[16] = "0123456789ABCDEF";

static void make_session_filename(const char *in, strbuf *out)
{
    if (!in || !*in)
        in = "Default Settings";

    while (*in) {
        /*
         * There are remarkably few punctuation characters that
         * aren't shell-special in some way or likely to be used as
         * separators in some file format or another! Hence we use
         * opt-in for safe characters rather than opt-out for
         * specific unsafe ones...
         */
	if (*in!='+' && *in!='-' && *in!='.' && *in!='@' && *in!='_' &&
            *in!=' ' &&
            !(*in >= '0' && *in <= '9') &&
            !(*in >= 'A' && *in <= 'Z') &&
            !(*in >= 'a' && *in <= 'z')) {
	    put_byte(out, '%');
	    put_byte(out, hex[((unsigned char) *in) >> 4]);
	    put_byte(out, hex[((unsigned char) *in) & 15]);
	} else
	    put_byte(out, *in);
	in++;
    }

    /* add extension */
    put_byte(out, '.');
    put_byte(out, 'a');
    put_byte(out, 't');
}

static void decode_session_filename(const char *in, strbuf *out)
{
    while (*in) {
	if (*in == '%' && in[1] && in[2]) {
	    int i, j;

	    i = in[1] - '0';
	    i -= (i > 9 ? 7 : 0);
	    j = in[2] - '0';
	    j -= (j > 9 ? 7 : 0);

	    put_byte(out, (i << 4) + j);
	    in += 3;
        } else if (*in == '.' && in[1] == 'a' && in[2] == 't' && in[4] == '\0') {
            /* skip extension */
            in += 3;
	} else {
	    put_byte(out, *in++);
	}
    }
}

static char *make_filename(int index, const char *subname)
{
    strbuf *sb = strbuf_new();
    char base[MAX_PATH];

    /* public documents + our app */
    SHGetFolderPath(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, base);
    strbuf_catf(sb, "%s\\%s", base, appname);

    /* the specific thing asked for */
    if (index == INDEX_SESSION) {
        strbuf_catf(sb, "\\%s\\", "sessions");
        make_session_filename(subname, sb);
    } else {
        strbuf_catf(sb, "%s",
                index == INDEX_DIR ? "" :
                index == INDEX_SESSIONDIR ? "\\sessions" :
                index == INDEX_HOSTKEYS ? "\\sshhostkeys" :
                index == INDEX_HOSTKEYS_TMP ? "\\sshhostkeys.tmp" :
                index == INDEX_RANDSEED ? "\\randomseed" :
                "\\ERROR");
    }
    return strbuf_to_str(sb);
}

struct settings_w {
    FILE *fp;
};

settings_w *open_settings_w(const char *sessionname, char **errmsg)
{
    char *filename;
    FILE *fp;
    *errmsg = NULL;

    /*
     * Start by making sure the putty directory and its sessions
     * subdir actually exist. Ignore error returns from mkdir since
     * they're perfectly likely to be `already exists', and any
     * other error will trip us up later on so there's no real need
     * to catch it now.
     */
    filename = make_filename(INDEX_DIR, sessionname);
    _mkdir(filename);
    sfree(filename);
    filename = make_filename(INDEX_SESSIONDIR, sessionname);
    _mkdir(filename);
    sfree(filename);

    filename = make_filename(INDEX_SESSION, sessionname);
    fp = fopen(filename, "w");
    if (!fp) {
        *errmsg = dupprintf("Unable to open %s: %s", filename, strerror(errno));
        sfree(filename);
        return NULL;                   /* can't open */
    }
    sfree(filename);

    settings_w *toret = snew(settings_w);
    toret->fp = fp;
    return toret;
}

void write_setting_s(settings_w *handle, const char *key, const char *value)
{
    fprintf(handle->fp, "%s=%s\n", key, value);
}

void write_setting_i(settings_w *handle, const char *key, int value)
{
    fprintf(handle->fp, "%s=%d\n", key, value);
}

void close_settings_w(settings_w *handle)
{
    fclose(handle->fp);
}

struct keyval {
    const char *key;
    const char *value;
};

static tree234 *xrmtree = NULL;

int keycmp(void *av, void *bv)
{
    struct keyval *a = (struct keyval *)av;
    struct keyval *b = (struct keyval *)bv;
    return strcmp(a->key, b->key);
}

const char *get_setting(const char *key)
{
    struct keyval tmp, *ret;
    tmp.key = key;
    if (xrmtree) {
        ret = find234(xrmtree, &tmp, NULL);
        if (ret)
            return ret->value;
    }
    return NULL;
}

struct settings_r {
    tree234 *t;
};


settings_r *open_settings_r(const char *sessionname)
{
    char *filename;
    FILE *fp;
    char *line;
    settings_r *toret;

    filename = make_filename(INDEX_SESSION, sessionname);
    fp = fopen(filename, "r");
    sfree(filename);
    if (!fp)
        return NULL;               /* can't open */

    toret = snew(settings_r);
    toret->t = newtree234(keycmp);

    while ( (line = fgetline(fp)) ) {
        char *value = strchr(line, '=');
        struct keyval *kv;

        if (!value) continue;
        *value++ = '\0';
        value[strcspn(value, "\r\n")] = '\0';   /* trim trailing NL */

        kv = snew(struct keyval);
        kv->key = dupstr(line);
        kv->value = dupstr(value);
        add234(toret->t, kv);

        sfree(line);
    }

    fclose(fp);

    return toret;
}

char *read_setting_s(settings_r *handle, const char *key)
{
    const char *val;
    struct keyval tmp, *kv;

    tmp.key = key;
    if (handle != NULL &&
        (kv = find234(handle->t, &tmp, NULL)) != NULL) {
        val = kv->value;
        assert(val != NULL);
    } else
        val = get_setting(key);

    if (!val)
        return NULL;
    else {
        return dupstr(val);
    }
}

int read_setting_i(settings_r *handle, const char *key, int defvalue)
{
    const char *val;
    struct keyval tmp, *kv;

    tmp.key = key;
    if (handle != NULL &&
        (kv = find234(handle->t, &tmp, NULL)) != NULL) {
        val = kv->value;
        assert(val != NULL);
    } else
        val = get_setting(key);

    if (!val)
    return defvalue;
    else
    return atoi(val);
}

FontSpec *read_setting_fontspec(settings_r *handle, const char *name)
{
    char *settingname;
    char *fontname;
    FontSpec *ret;
    int isbold, height, charset;

    fontname = read_setting_s(handle, name);
    if (!fontname)
	return NULL;

    settingname = dupcat(name, "IsBold", NULL);
    isbold = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (isbold == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "CharSet", NULL);
    charset = read_setting_i(handle, settingname, -1);
    sfree(settingname);
    if (charset == -1) {
        sfree(fontname);
        return NULL;
    }

    settingname = dupcat(name, "Height", NULL);
    height = read_setting_i(handle, settingname, INT_MIN);
    sfree(settingname);
    if (height == INT_MIN) {
        sfree(fontname);
        return NULL;
    }

    ret = fontspec_new(fontname, isbold, height, charset);
    sfree(fontname);
    return ret;
}

void write_setting_fontspec(settings_w *handle,
                            const char *name, FontSpec *font)
{
    char *settingname;

    write_setting_s(handle, name, font->name);
    settingname = dupcat(name, "IsBold", NULL);
    write_setting_i(handle, settingname, font->isbold);
    sfree(settingname);
    settingname = dupcat(name, "CharSet", NULL);
    write_setting_i(handle, settingname, font->charset);
    sfree(settingname);
    settingname = dupcat(name, "Height", NULL);
    write_setting_i(handle, settingname, font->height);
    sfree(settingname);
}

Filename *read_setting_filename(settings_r *handle, const char *name)
{
    char *tmp = read_setting_s(handle, name);
    if (tmp) {
        Filename *ret = filename_from_str(tmp);
        sfree(tmp);
        return ret;
    } else
        return NULL;
}

void write_setting_filename(settings_w *handle,
                            const char *name, Filename *result)
{
    write_setting_s(handle, name, result->path);
}

void close_settings_r(settings_r *handle)
{
    struct keyval *kv;

    if (!handle)
        return;

    while ( (kv = index234(handle->t, 0)) != NULL) {
        del234(handle->t, kv);
        sfree((char *)kv->key);
        sfree((char *)kv->value);
        sfree(kv);
    }

    freetree234(handle->t);
    sfree(handle);
}

void del_settings(const char *sessionname)
{
    char *filename;
    filename = make_filename(INDEX_SESSION, sessionname);
    _unlink(filename);
    sfree(filename);
}

struct settings_e {
    DIR *dp;
};

settings_e *enum_settings_start(void)
{

    DIR *dp;
    char *filename;

    filename = make_filename(INDEX_SESSIONDIR, NULL);
    dp = opendir(filename);
    sfree(filename);

    settings_e *toret = snew(settings_e);
    toret->dp = dp;
    return toret;
}

bool enum_settings_next(settings_e *handle, strbuf *out)
{
    struct dirent *de;
    struct stat st;
    strbuf *fullpath;

    if (!handle->dp)
        return NULL;

    fullpath = strbuf_new();

    char *sessiondir = make_filename(INDEX_SESSIONDIR, NULL);
    put_datapl(fullpath, ptrlen_from_asciz(sessiondir));
    sfree(sessiondir);
    put_byte(fullpath, '/');

    size_t baselen = fullpath->len;

    while ( (de = readdir(handle->dp)) != NULL ) {
        fullpath->len = baselen;
	put_datapl(fullpath, ptrlen_from_asciz(de->d_name));

        if (stat(fullpath->s, &st) < 0 || !S_ISREG(st.st_mode))
            continue;                  /* try another one */

        decode_session_filename(de->d_name, out);
	strbuf_free(fullpath);
        return true;
    }

    strbuf_free(fullpath);
    return false;
}

void enum_settings_finish(settings_e *handle)
{
    if (handle->dp)
        closedir(handle->dp);
    sfree(handle);
}

int verify_host_key(const char *hostname, int port, const char *keytype, const char *key)
{
    FILE *fp;
    char *filename;
    char *line;
    int ret;

    filename = make_filename(INDEX_HOSTKEYS, NULL);
    fp = fopen(filename, "r");
    sfree(filename);
    if (!fp)
        return 1;               /* key does not exist */

    ret = 1;
    while ( (line = fgetline(fp)) ) {
    int i;
    char *p = line;
    char porttext[20];

    line[strcspn(line, "\n")] = '\0';   /* strip trailing newline */

    i = strlen(keytype);
    if (strncmp(p, keytype, i)) goto done;
    p += i;

    if (*p != '@') goto done;
    p++;

    sprintf(porttext, "%d", port);
    i = strlen(porttext);
    if (strncmp(p, porttext, i)) goto done;
    p += i;

    if (*p != ':') goto done;
    p++;

    i = strlen(hostname);
    if (strncmp(p, hostname, i)) goto done;
    p += i;

    if (*p != ' ') goto done;
    p++;

    /*
     * Found the key. Now just work out whether it's the right
     * one or not.
     */
    if (!strcmp(p, key)) ret = 0;               /* key matched OK */
    else ret = 2;               /* key mismatch */

    done:
    sfree(line);
    if (ret != 1) break;
    }

    fclose(fp);
    return ret;
}

bool have_ssh_host_key(const char *hostname, int port,
                       const char *keytype)
{
    /*
     * If we have a host key, verify_host_key will return 0 or 2.
     * If we don't have one, it'll return 1.
     */
    return verify_host_key(hostname, port, keytype, "") != 1;
}

void store_host_key(const char *hostname, int port,
            const char *keytype, const char *key)
{
    FILE *rfp, *wfp;
    char *newtext, *line;
    int headerlen;
    char *filename, *tmpfilename;

    newtext = dupprintf("%s@%d:%s %s\n", keytype, port, hostname, key);
    headerlen = 1 + strcspn(newtext, " ");   /* count the space too */

    /*
     * Open both the old file and a new file.
     */
    tmpfilename = make_filename(INDEX_HOSTKEYS_TMP, NULL);
    wfp = fopen(tmpfilename, "w");
    sfree(tmpfilename);
    if (!wfp) {
        char *dir;

        dir = make_filename(INDEX_DIR, NULL);
        _mkdir(dir);
        sfree(dir);
        wfp = fopen(tmpfilename, "w");
    }
    if (!wfp)
        return;

    filename = make_filename(INDEX_HOSTKEYS, NULL);
    rfp = fopen(filename, "r");
    sfree(filename);

    /*
     * Copy all lines from the old file to the new one that _don't_
     * involve the same host key identifier as the one we're adding.
     */
    if (rfp) {
        while ( (line = fgetline(rfp)) ) {
            if (strncmp(line, newtext, headerlen))
                fputs(line, wfp);
        }
        fclose(rfp);
    }

    /*
     * Now add the new line at the end.
     */
    fputs(newtext, wfp);

    fclose(wfp);

    _unlink(filename);

    rename(tmpfilename, filename);

    sfree(newtext);
}

void read_random_seed(noise_consumer_t consumer)
{
    char *fname;
    HANDLE seedf;

    fname = make_filename(INDEX_RANDSEED, NULL);
    seedf = CreateFile(fname, GENERIC_READ,
               FILE_SHARE_READ | FILE_SHARE_WRITE,
               NULL, OPEN_EXISTING, 0, NULL);
    sfree(fname);

    if (seedf != INVALID_HANDLE_VALUE) {
        while (1) {
            char buf[1024];
            DWORD len;

            if (ReadFile(seedf, buf, sizeof(buf), &len, NULL) && len)
                consumer(buf, len);
            else
                break;
        }
        CloseHandle(seedf);
    }
}

void write_random_seed(void *data, int len)
{
    char *fname;
    HANDLE seedf;

    fname = make_filename(INDEX_RANDSEED, NULL);
    seedf = CreateFile(fname, GENERIC_WRITE, 0,
               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    sfree(fname);

    if (seedf != INVALID_HANDLE_VALUE) {
        DWORD lenwritten;

        WriteFile(seedf, data, len, &lenwritten, NULL);
        CloseHandle(seedf);
    }
}

/* Adds a new entry to the jumplist entries in the registry. */
int add_to_jumplist_registry(const char *item)
{
    /* We don't use the jumplist, so disable it */
    return JUMPLISTREG_OK;
}

/* Removes an item from the jumplist entries in the registry. */
int remove_from_jumplist_registry(const char *item)
{
    /* We don't use the jumplist, so disable it */
    return JUMPLISTREG_OK;
}

/* Returns the jumplist entries from the registry. Caller must free
 * the returned pointer. */
char *get_jumplist_registry_entries (void)
{
    /* We don't use the jumplist, so disable it */
    char *list_value;
    list_value = snewn(2, char);
    *list_value = '\0';
    *(list_value + 1) = '\0';
    return list_value;
}

void cleanup_all(void)
{
    char *fname;

    fname = make_filename(INDEX_RANDSEED, NULL);
    remove(fname);
    sfree(fname);
}
