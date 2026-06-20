/*
 * main.c - PQ-Zip entry point + GTK3 GUI.
 *
 * With command-line arguments it dispatches to the CLI (cli.c); with none it
 * launches the graphical interface. The actual compress/extract work runs on
 * a worker thread so the Argon2id KDF never freezes the UI.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sodium.h>
#include "pqzip.h"
#include "secure_buffer.h"

#ifndef PQZIP_VERSION
#define PQZIP_VERSION "1.0.6"
#endif
#define APP_ID "org.pqzip.PQZip"

int cli_main(int argc, char **argv);   /* from cli.c */

/* Cyber-styled dark theme (green-accented for the "zip" identity). */
static const char *APP_CSS =
    "window, .pqz-root, scrolledwindow, viewport { background-color: #070f0b; color: #c8ffe0; }"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a160f, #0e2618, #0a160f);"
    "  border-bottom: 1px solid #39ff14;"
    "  box-shadow: 0 1px 8px rgba(57,255,20,0.30);"
    "  min-height: 40px;"
    "}"
    ".hb-title {"
    "  color: #39ff14; font-family: monospace; font-weight: bold; letter-spacing: 2px;"
    "}"
    "headerbar button { padding: 2px 10px; margin: 4px 2px; min-height: 0; min-width: 0; }"
    "headerbar button.titlebutton { padding: 2px; margin: 2px; min-height: 22px; min-width: 22px; }"
    "label { color: #9fe6c2; font-family: monospace; }"
    ".field-label { color: #5fc98f; letter-spacing: 1px; }"
    ".brand {"
    "  color: #39ff14; font-family: monospace; font-weight: bold;"
    "  font-size: 22px; letter-spacing: 6px;"
    "}"
    ".subtitle { color: #3d8f5d; font-size: 10px; letter-spacing: 4px; }"
    "entry {"
    "  background-color: #0c1a12; color: #d8ffe8; border: 1px solid #14492a;"
    "  border-radius: 4px; padding: 7px; font-family: monospace; caret-color: #39ff14;"
    "}"
    "entry:focus { border-color: #39ff14; box-shadow: 0 0 6px rgba(57,255,20,0.6); }"
    "combobox box, combobox button, combobox {"
    "  background-color: #0c1a12; color: #d8ffe8; border: 1px solid #14492a;"
    "  border-radius: 4px; font-family: monospace;"
    "}"
    "combobox button:hover { border-color: #39ff14; }"
    "treeview, textview, .view {"
    "  background-color: #0c1a12; color: #d8ffe8; font-family: monospace;"
    "}"
    "treeview:selected { background-color: #14492a; color: #ffffff; }"
    ".list-scroll { border: 1px solid #14492a; border-radius: 4px; }"
    "radiobutton, checkbutton { color: #9fe6c2; font-family: monospace; }"
    "radiobutton check, checkbutton check {"
    "  background-color: #0c1a12; border: 1px solid #2a8050;"
    "}"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #39ff14; border-color: #39ff14;"
    "}"
    /* All buttons: black text on a readable neon-green face. The label color
     * is forced on the button AND its child label, in every state, so no GTK
     * theme can override it back to white. */
    "button {"
    "  background: #1bd96a; border: 1px solid #39ff14;"
    "  border-radius: 4px; padding: 7px 14px; font-family: monospace; letter-spacing: 1px;"
    "}"
    "button:hover { background: #39ff14; box-shadow: 0 0 8px rgba(57,255,20,0.45); }"
    "button:active { background: #14b050; }"
    "button:disabled { background: #14492a; border-color: #16413e; }"
    "button, button:hover, button:active, button:checked,"
    "button label, button:hover label, button:active label,"
    ".action-button, .action-button:hover, .action-button label,"
    ".action-button:hover label { color: #000000; }"
    "button:disabled, button:disabled label { color: #5a8f70; }"
    ".action-button {"
    "  background: linear-gradient(90deg, #00b3c4, #39ff14);"
    "  font-weight: bold; letter-spacing: 2px; border: 1px solid #39ff14;"
    "}"
    ".action-button:hover { box-shadow: 0 0 14px rgba(57,255,20,0.8); }"
    "progressbar text { color: #9fffc8; font-family: monospace; font-size: 10px; }"
    "progressbar trough {"
    "  background-color: #0c1a12; border: 1px solid #14492a; border-radius: 4px; min-height: 18px;"
    "}"
    "progressbar progress {"
    "  background: linear-gradient(90deg, #00b3c4, #39ff14); border-radius: 4px;"
    "  min-height: 18px; box-shadow: 0 0 10px rgba(57,255,20,0.6);"
    "}"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

#define PASSWORD_MAX 4096

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *radio_compress;
    GtkWidget *radio_extract;
    /* compress widgets */
    GtkWidget *inputs_view;
    GtkListStore *inputs_store;
    GtkWidget *compress_box;
    GtkWidget *out_entry;
    GtkWidget *cipher_combo;
    GtkWidget *kdf_combo;
    GtkWidget *hybrid_check;
    GtkWidget *level_combo;
    /* extract widgets */
    GtkWidget *extract_box;
    GtkWidget *arc_entry;
    GtkWidget *dest_entry;
    /* shared */
    GtkWidget *pass_entry;
    GtkWidget *reveal_check;
    GtkWidget *run_button;
    GtkWidget *progress;
    GtkWidget *status;
    guint      pulse_id;
    gboolean   pulsing;
    volatile int window_gone;
    Job * volatile current_job;
} App;

struct Job {
    App        *app;
    int         compress;
    /* compress inputs (owned copies) */
    char      **inputs;
    int         n_inputs;
    char        out_path[4096];   /* .pqz path (compress) or dest dir (extract) */
    char        arc_path[4096];   /* input .pqz (extract) */
    char        password[PASSWORD_MAX];
    cipher_id_t cipher;
    kdf_level_t level;
    int         hybrid;
    int         zlevel;
    /* results */
    int         rc;
    char        err[256];
    /* progress */
    GMutex            plock;
    double            fraction;
    uint64_t          done_bytes;
    uint64_t          total_bytes;
    volatile int      cancelled;
    volatile gint     idle_queued;
};

/* ----- progress plumbing ----------------------------------------------- */

static void human_size(uint64_t b, char *out, size_t n) {
    const char *u[] = { "B", "KB", "MB", "GB", "TB" };
    double v = (double)b; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(out, n, i == 0 ? "%.0f %s" : "%.1f %s", v, u[i]);
}

static gboolean update_progress_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    g_atomic_int_set(&job->idle_queued, 0);
    if (app->window_gone) return G_SOURCE_REMOVE;
    app->pulsing = FALSE;
    GtkProgressBar *pb = GTK_PROGRESS_BAR(app->progress);
    g_mutex_lock(&job->plock);
    double   fraction = job->fraction;
    uint64_t done = job->done_bytes, tot = job->total_bytes;
    g_mutex_unlock(&job->plock);
    gtk_progress_bar_set_fraction(pb, fraction);
    char d[32], t[32], txt[96];
    human_size(done, d, sizeof d);
    human_size(tot, t, sizeof t);
    if (tot)
        snprintf(txt, sizeof txt, "%.0f%%   %s / %s", fraction * 100.0, d, t);
    else
        snprintf(txt, sizeof txt, "%s", d);
    gtk_progress_bar_set_text(pb, txt);
    return G_SOURCE_REMOVE;
}

static int progress_cb(uint64_t done, uint64_t total, void *user) {
    Job *job = user;
    g_mutex_lock(&job->plock);
    job->done_bytes = done;
    job->total_bytes = total;
    job->fraction = total ? (double)done / (double)total : 0.0;
    g_mutex_unlock(&job->plock);
    if (g_atomic_int_compare_and_exchange(&job->idle_queued, 0, 1))
        g_idle_add(update_progress_idle, job);
    return job->cancelled;
}

/* ----- worker ----------------------------------------------------------- */

static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

static void stop_pulse(App *app) {
    app->pulsing = FALSE;
    if (app->pulse_id) { g_source_remove(app->pulse_id); app->pulse_id = 0; }
}

static void free_app(App *app) { stop_pulse(app); g_free(app); }

static void job_free_inputs(Job *job) {
    if (job->inputs) {
        for (int i = 0; i < job->n_inputs; i++) g_free(job->inputs[i]);
        g_free(job->inputs);
        job->inputs = NULL;
    }
}

static gboolean job_finished_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    app->current_job = NULL;
    stop_pulse(app);

    if (app->window_gone) {
        sodium_munlock(job->password, sizeof(job->password));
        job_free_inputs(job);
        g_mutex_clear(&job->plock);
        g_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        free_app(app);
        return G_SOURCE_REMOVE;
    }

    gtk_widget_set_sensitive(app->run_button, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), job->rc == 0 ? 1.0 : 0.0);

    if (job->rc == 0) {
        gchar *msg = g_strdup_printf("\xE2\x9C\x94 %s\n%s",
                                     job->compress ? "Archive written to:" : "Extracted into:",
                                     job->compress ? job->out_path : job->out_path);
        set_status(app, "status-ok", msg);
        g_free(msg);
    } else {
        gchar *msg = g_strdup_printf("\xE2\x9C\x96 %s", job->err);
        set_status(app, "status-err", msg);
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", job->err);
        gtk_dialog_run(GTK_DIALOG(d));
        gtk_widget_destroy(d);
    }

    sodium_munlock(job->password, sizeof(job->password));
    job_free_inputs(job);
    g_mutex_clear(&job->plock);
    g_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress));
    return G_SOURCE_CONTINUE;
}

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    if (job->compress) {
        job->rc = pqz_create((const char *const *)job->inputs, job->n_inputs,
                             job->out_path, job->password, job->cipher, job->level,
                             job->hybrid, job->zlevel, progress_cb, job,
                             job->err, sizeof(job->err));
    } else {
        job->rc = pqz_extract(job->arc_path, job->out_path, job->password,
                              progress_cb, job, job->err, sizeof(job->err));
    }
    g_idle_add(job_finished_idle, job);
    return NULL;
}

/* ----- UI callbacks ----------------------------------------------------- */

static void on_reveal_toggled(GtkToggleButton *btn, gpointer user) {
    App *app = user;
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), gtk_toggle_button_get_active(btn));
}

/* Add one path string to the inputs list store. */
static void inputs_add(App *app, const char *path) {
    GtkTreeIter it;
    gtk_list_store_append(app->inputs_store, &it);
    gtk_list_store_set(app->inputs_store, &it, 0, path, -1);
}

static void on_add_files(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Add files",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Add", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dlg), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dlg));
        for (GSList *l = files; l; l = l->next) { inputs_add(app, l->data); g_free(l->data); }
        g_slist_free(files);
    }
    gtk_widget_destroy(dlg);
}

static void on_add_folder(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Add folder",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Add", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        inputs_add(app, f); g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_remove_input(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->inputs_view));
    GtkTreeModel *model;
    GtkTreeIter it;
    if (gtk_tree_selection_get_selected(sel, &model, &it))
        gtk_list_store_remove(app->inputs_store, &it);
}

static void browse_entry(App *app, GtkWidget *entry, GtkFileChooserAction action,
                         const char *title) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title,
        GTK_WINDOW(app->window), action,
        "_Cancel", GTK_RESPONSE_CANCEL,
        action == GTK_FILE_CHOOSER_ACTION_SAVE ? "_Save" : "_Select", GTK_RESPONSE_ACCEPT, NULL);
    if (action == GTK_FILE_CHOOSER_ACTION_SAVE)
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(entry), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_browse_out(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_entry(app, app->out_entry, GTK_FILE_CHOOSER_ACTION_SAVE, "Output .pqz file");
}
static void on_browse_arc(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_entry(app, app->arc_entry, GTK_FILE_CHOOSER_ACTION_OPEN, "Select .pqz archive");
}
static void on_browse_dest(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_entry(app, app->dest_entry, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "Destination folder");
}

static void on_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn;
    App *app = user;
    gboolean comp = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_compress));
    gtk_widget_set_visible(app->compress_box, comp);
    gtk_widget_set_visible(app->extract_box, !comp);
    gtk_button_set_label(GTK_BUTTON(app->run_button), comp ? "COMPRESS" : "EXTRACT");
}

static void warn(App *app, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char msg[512]; vsnprintf(msg, sizeof(msg), fmt, ap); va_end(ap);
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void on_run(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    gboolean comp = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_compress));
    const char *pw = gtk_entry_get_text(GTK_ENTRY(app->pass_entry));

    if (!pw || !*pw) { warn(app, "Please enter a password."); return; }
    if (strlen(pw) >= PASSWORD_MAX) {
        warn(app, "Password is too long (maximum %d characters).", PASSWORD_MAX - 1); return;
    }

    Job *job = g_new0(Job, 1);
    g_mutex_init(&job->plock);
    sodium_mlock(job->password, sizeof(job->password));
    job->app = app;
    job->compress = comp ? 1 : 0;
    g_strlcpy(job->password, pw, sizeof(job->password));

    if (comp) {
        const char *out = gtk_entry_get_text(GTK_ENTRY(app->out_entry));
        if (!out || !*out) { warn(app, "Please choose an output .pqz file."); goto reject; }
        if (strlen(out) >= sizeof(job->out_path)) { warn(app, "Output path is too long."); goto reject; }

        /* Snapshot the input list. */
        int n = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(app->inputs_store), NULL);
        if (n == 0) { warn(app, "Add at least one file or folder to compress."); goto reject; }
        job->inputs = g_new0(char *, n);
        GtkTreeIter it;
        int i = 0;
        gboolean ok = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(app->inputs_store), &it);
        while (ok && i < n) {
            char *p = NULL;
            gtk_tree_model_get(GTK_TREE_MODEL(app->inputs_store), &it, 0, &p, -1);
            job->inputs[i++] = p;   /* take ownership of the allocated string */
            ok = gtk_tree_model_iter_next(GTK_TREE_MODEL(app->inputs_store), &it);
        }
        job->n_inputs = i;
        g_strlcpy(job->out_path, out, sizeof(job->out_path));

        const gchar *cid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->cipher_combo));
        job->cipher = cid ? (cipher_id_t)atoi(cid) : CIPHER_AES_256_GCM;
        const gchar *kid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->kdf_combo));
        job->level = kid ? (kdf_level_t)atoi(kid) : KDF_MEDIUM;
        const gchar *lid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->level_combo));
        job->zlevel = lid ? atoi(lid) : 6;
        job->hybrid = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->hybrid_check)) ? 1 : 0;
    } else {
        const char *arc = gtk_entry_get_text(GTK_ENTRY(app->arc_entry));
        const char *dest = gtk_entry_get_text(GTK_ENTRY(app->dest_entry));
        if (!arc || !*arc) { warn(app, "Please choose a .pqz archive to extract."); goto reject; }
        if (!dest || !*dest) { warn(app, "Please choose a destination folder."); goto reject; }
        if (strlen(arc) >= sizeof(job->arc_path) || strlen(dest) >= sizeof(job->out_path)) {
            warn(app, "A path is too long."); goto reject;
        }
        g_strlcpy(job->arc_path, arc, sizeof(job->arc_path));
        g_strlcpy(job->out_path, dest, sizeof(job->out_path));
    }

    gtk_widget_set_sensitive(app->run_button, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "working\xE2\x80\xA6");
    set_status(app, "status-run",
               comp ? "\xE2\x96\xB6 Compressing\xE2\x80\xA6 (deriving key, this may take a moment)"
                    : "\xE2\x96\xB6 Extracting\xE2\x80\xA6 (deriving key, this may take a moment)");

    app->pulsing = TRUE;
    if (app->pulse_id == 0) app->pulse_id = g_timeout_add(110, pulse_cb, app);

    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));

    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqzip-worker", worker_thread, job, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->current_job = NULL;
        stop_pulse(app);
        gtk_widget_set_sensitive(app->run_button, TRUE);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        sodium_munlock(job->password, sizeof(job->password));
        job_free_inputs(job);
        g_mutex_clear(&job->plock);
        g_free(job);
        if (gerr) g_error_free(gerr);
    } else {
        g_thread_unref(t);
    }
    return;

reject:
    sodium_munlock(job->password, sizeof(job->password));
    job_free_inputs(job);
    g_mutex_clear(&job->plock);
    g_free(job);
}

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const gchar *features =
        "PQ-Zip is a post-quantum compressing archiver.\n\n"
        "Features:\n"
        "\xE2\x80\xA2 Compress files and/or directories into one .pqz archive\n"
        "\xE2\x80\xA2 DEFLATE (zlib) compression, selectable level\n"
        "\xE2\x80\xA2 Password-protected, authenticated encryption:\n"
        "  AES-256-GCM, XChaCha20-Poly1305 or ChaCha20-Poly1305\n"
        "\xE2\x80\xA2 Post-quantum hybrid KEM (Kyber-1024 + X448)\n"
        "\xE2\x80\xA2 Argon2id key derivation (Basic / Medium / Strong)\n"
        "\xE2\x80\xA2 Chunked streaming with per-chunk authentication\n"
        "\xE2\x80\xA2 Hardened memory: keys and passwords are locked, non-dumpable\n"
        "\xE2\x80\xA2 Command-line interface for scripting and servers";

    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQ-Zip");
    gtk_about_dialog_set_version(ad, PQZIP_VERSION);
    gtk_about_dialog_set_comments(ad, features);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "\xC2\xA9 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pqzip");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- layout ----------------------------------------------------------- */

static GtkWidget *labeled_row(const char *text, GtkWidget *widget, GtkWidget *extra) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_widget_set_size_request(lbl, 110, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    return box;
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    Job *job = app->current_job;
    if (job) job->cancelled = 1;
    else free_app(app);
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ-Zip");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 880, -1);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pqzip");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title_lbl = gtk_label_new("PQ-ZIP  \xC2\xB7  v" PQZIP_VERSION);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "pqz-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 18);

    gtk_container_add(GTK_CONTAINER(app->window), root);

    GtkWidget *brand = gtk_label_new("\xE2\x9D\x96 P Q - Z I P");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    GtkWidget *sub = gtk_label_new("POST-QUANTUM  COMPRESSION");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "subtitle");
    gtk_box_pack_start(GTK_BOX(root), sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 6);

    /* Mode */
    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->radio_compress = gtk_radio_button_new_with_label(NULL, "Compress");
    app->radio_extract = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->radio_compress), "Extract");
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_compress, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_extract, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Operation:", mode_box, NULL), FALSE, FALSE, 0);

    /* ---- Compress box: two columns to stay wide rather than tall ---- */
    app->compress_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 18);
    GtkWidget *comp_left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *comp_right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_box_pack_start(GTK_BOX(app->compress_box), comp_left, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(app->compress_box), comp_right, TRUE, TRUE, 0);

    app->inputs_store = gtk_list_store_new(1, G_TYPE_STRING);
    app->inputs_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->inputs_store));
    g_object_unref(app->inputs_store);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(app->inputs_view), FALSE);
    GtkCellRenderer *rend = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
        "Path", rend, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->inputs_view), col);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroll, -1, 120);
    gtk_style_context_add_class(gtk_widget_get_style_context(scroll), "list-scroll");
    gtk_container_add(GTK_CONTAINER(scroll), app->inputs_view);
    gtk_box_pack_start(GTK_BOX(comp_left),
                       labeled_row("Inputs:", scroll, NULL), TRUE, TRUE, 0);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *add_f = gtk_button_new_with_label("Add Files\xE2\x80\xA6");
    GtkWidget *add_d = gtk_button_new_with_label("Add Folder\xE2\x80\xA6");
    GtkWidget *rm = gtk_button_new_with_label("Remove");
    g_signal_connect(add_f, "clicked", G_CALLBACK(on_add_files), app);
    g_signal_connect(add_d, "clicked", G_CALLBACK(on_add_folder), app);
    g_signal_connect(rm, "clicked", G_CALLBACK(on_remove_input), app);
    gtk_box_pack_start(GTK_BOX(btn_box), add_f, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), add_d, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), rm, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(comp_left),
                       labeled_row("", btn_box, NULL), FALSE, FALSE, 0);

    app->out_entry = gtk_entry_new();
    GtkWidget *out_btn = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(out_btn, "clicked", G_CALLBACK(on_browse_out), app);
    gtk_box_pack_start(GTK_BOX(comp_left),
                       labeled_row("Output .pqz:", app->out_entry, out_btn), FALSE, FALSE, 0);

    app->cipher_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "1", "AES-256-GCM (default)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "2", "XChaCha20-Poly1305");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "3", "ChaCha20-Poly1305");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->cipher_combo), "1");
    gtk_box_pack_start(GTK_BOX(comp_right),
                       labeled_row("Cipher:", app->cipher_combo, NULL), FALSE, FALSE, 0);

    app->kdf_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "0", "Basic (256 MiB)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "1", "Medium (1 GiB) \xE2\x80\x94 minimum");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "2", "Strong (4 GiB)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->kdf_combo), "1");
    gtk_box_pack_start(GTK_BOX(comp_right),
                       labeled_row("Key strength:", app->kdf_combo, NULL), FALSE, FALSE, 0);

    app->level_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->level_combo), "1", "Fast (1)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->level_combo), "6", "Balanced (6)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->level_combo), "9", "Maximum (9)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->level_combo), "6");
    gtk_box_pack_start(GTK_BOX(comp_right),
                       labeled_row("Compression:", app->level_combo, NULL), FALSE, FALSE, 0);

    app->hybrid_check = gtk_check_button_new_with_label("Post-quantum hybrid (Kyber-1024 + X448)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->hybrid_check), TRUE);
    gtk_box_pack_start(GTK_BOX(comp_right),
                       labeled_row("Hybrid PQC:", app->hybrid_check, NULL), FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), app->compress_box, FALSE, FALSE, 0);

    /* ---- Extract box ---- */
    app->extract_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    app->arc_entry = gtk_entry_new();
    GtkWidget *arc_btn = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(arc_btn, "clicked", G_CALLBACK(on_browse_arc), app);
    gtk_box_pack_start(GTK_BOX(app->extract_box),
                       labeled_row("Archive .pqz:", app->arc_entry, arc_btn), FALSE, FALSE, 0);
    app->dest_entry = gtk_entry_new();
    GtkWidget *dest_btn = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(dest_btn, "clicked", G_CALLBACK(on_browse_dest), app);
    gtk_box_pack_start(GTK_BOX(app->extract_box),
                       labeled_row("Extract to:", app->dest_entry, dest_btn), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), app->extract_box, FALSE, FALSE, 0);

    /* ---- Password (shared) ---- */
    GtkEntryBuffer *pass_buf = secure_entry_buffer_new();
    app->pass_entry = gtk_entry_new_with_buffer(pass_buf);
    g_object_unref(pass_buf);
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    app->reveal_check = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(app->reveal_check, "toggled", G_CALLBACK(on_reveal_toggled), app);
    gtk_box_pack_start(GTK_BOX(root),
                       labeled_row("Password:", app->pass_entry, app->reveal_check),
                       FALSE, FALSE, 0);

    app->run_button = gtk_button_new_with_label("COMPRESS");
    gtk_widget_set_hexpand(app->run_button, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->run_button), "action-button");
    g_signal_connect(app->run_button, "clicked", G_CALLBACK(on_run), app);
    gtk_box_pack_start(GTK_BOX(root), app->run_button, FALSE, FALSE, 8);

    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "idle");
    gtk_box_pack_start(GTK_BOX(root), app->progress, FALSE, FALSE, 0);
    app->status = gtk_label_new("Ready.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->status, FALSE, FALSE, 0);

    g_signal_connect(app->radio_compress, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->radio_extract, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_widget_show_all(app->window);
    /* Start in compress mode: hide the extract widgets. */
    gtk_widget_set_visible(app->extract_box, FALSE);
}

int main(int argc, char **argv) {
    if (pqz_crypto_init() != 0) {
        g_printerr("Failed to initialise crypto library.\n");
        return 1;
    }
    /* Any arguments -> command-line mode. No arguments -> GUI. */
    if (argc > 1) return cli_main(argc, argv);

    /* Disable the AT-SPI accessibility bridge before GTK initialises so it
     * doesn't emit "Couldn't connect to accessibility bus" warnings in
     * environments where that bus is unavailable (e.g. running as root /
     * inside containers). NO_AT_BRIDGE covers GTK3; GTK_A11Y covers GTK4. */
    g_setenv("NO_AT_BRIDGE", "1", TRUE);
    g_setenv("GTK_A11Y", "none", TRUE);

    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
