namespace XyloCode.SysAdminTools
{
    public interface IUser
    {
        string UserPrincipalName { get; }
        string Name { get; }
        string Phone {  get; }
        string Email {  get; }
    }
}
