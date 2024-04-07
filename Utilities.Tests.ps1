BeforeAll {
    . $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe "Test-FirewallRuleShouldBeEnabled" {
    It "If the time is within the threshold value, it returns true" {
        $LastAccessTime = [System.DateTime]::new(2000, 12, 25, 1, 0, 0)
        $TimeToDisableRule = 2 * 60 * 60
        $Now = [System.DateTime]::new(2000, 12, 25, 2, 59, 59)
        Test-FirewallRuleShouldBeEnabled -LastAccessTime $LastAccessTime -TimeToDisableRule $TimeToDisableRule -Now $Now |
        Should -BeTrue
    }
    It "If the time is out of date, it returns false" {
        $LastAccessTime = [System.DateTime]::new(2000, 12, 25, 1, 0, 0)
        $TimeToDisableRule = 2 * 60 * 60
        $Now = [System.DateTime]::new(2000, 12, 25, 3, 0, 0)
        Test-FirewallRuleShouldBeEnabled -LastAccessTime $LastAccessTime -TimeToDisableRule $TimeToDisableRule -Now $Now |
        Should -BeFalse
    }
}
