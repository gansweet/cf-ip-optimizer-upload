#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

extern int cfip_main(int, char **);
static char g_port[16], g_html[1200];

static void *run(void *a) {
    (void)a;
    char *av[] = { "cfip", "--no-browser", g_port, g_html, NULL };
    cfip_main(4, av);
    return NULL;
}

/* Core.start(filesDir, port)：数据目录 = filesDir，前端文件 = filesDir/web/index.html */
JNIEXPORT void JNICALL Java_com_amos_cfip_Core_start(JNIEnv *e, jclass k, jstring dir, jint port) {
    static int started;
    (void)k;
    if (started) return;
    started = 1;
    const char *d = (*e)->GetStringUTFChars(e, dir, NULL);
    if (!d) return;
    setenv("CFIP_HOME", d, 1);
    snprintf(g_html, sizeof g_html, "%s/web/index.html", d);
    snprintf(g_port, sizeof g_port, "%d", (int)port);
    (*e)->ReleaseStringUTFChars(e, dir, d);
    pthread_t t;
    if (!pthread_create(&t, NULL, run, NULL)) pthread_detach(t);
}
