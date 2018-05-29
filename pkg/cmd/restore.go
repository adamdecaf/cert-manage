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
 
package cmd 
 
import ( 
	"fmt" 
	"github.com/adamdecaf/cert-manage/pkg/store" 
) 
 
func RestoreForApp(app, path string) error { 
	s, err := store.ForApp(app) 
	if err != nil { 
		return err 
	} 
	err = s.Restore(path) 
	if err == nil { 
		fmt.Println("Restore completed successfully") 
	} 
	return err 
} 
 
func RestoreForPlatform(path string) error { 
	err := store.Platform().Restore(path) 
	if err == nil { 
		fmt.Println("Restore completed successfully") 
	} 
	return err 
} 
