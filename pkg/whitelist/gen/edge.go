// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
