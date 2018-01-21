package gen

// From https://github.com/adamdecaf/cert-manage/issues/108
// We should be able to scrape browser history (e.g. urls) from Microsoft Edge,
// however that's a bit more complicated as the files are seemingly always locked
// to other readers.
//
// The file is located here:
// C:\Users\User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat
//
// There are utilities available to snapshot the fs path and then read/copy files.
// https://github.com/candera/shadowspawn
// https://answers.microsoft.com/en-us/ie/forum/msedge/browsing-history-location-of-edge-browser/488ff6d5-12da-49e8-beff-78d2c2eb0542
