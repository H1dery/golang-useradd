package main

import (
  //  "fmt"
    wapi "github.com/iamacarpet/go-win64api"
)

func main(){
    username := "caisi123"
    password := "abc.123"
    fullname := ""
    groupname := "administrators"
    groupuser := []string{"caisi123"}
    wapi.UserAdd(username, fullname, password)
    wapi.LocalGroupAddMembers(groupname,groupuser)

    //users, err := wapi.ListLocalUsers()
}
