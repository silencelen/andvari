package io.silencelen.andvari.app

/** A release build has no check of the phone's crypto in Settings, and none of the vector files it reads (src/debug has them). */
internal val phoneCheck: PhoneCheckEntry? = null
