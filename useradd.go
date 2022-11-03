package main

import (
  //  "fmt"
    wapi "github.com/iamacarpet/go-win64api"
)

func main(){
    username := "testtest"
    password := "abc.123"
    fullname := ""
    groupname := "administrators"
    groupuser := []string{"testtest"}
    wapi.UserAdd(username, fullname, password)
    wapi.LocalGroupAddMembers(groupname,groupuser)

    //users, err := wapi.ListLocalUsers()
}
