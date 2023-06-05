class ImplementationTargetError(Exception):
    '''Raised when the implementation target returns an error'''
    pass


class RemediationTargetError(Exception):
    '''Raised when the remediation target returns an error'''
    pass


class RemediationFixInvalid(Exception):
    '''Raised when the remediation does not fix the implementation'''
    pass
