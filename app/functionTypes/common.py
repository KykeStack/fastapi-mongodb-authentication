from typing import NewType, Union

FunctionStatus = NewType('FunctionStatus', dict[str: bool, str: int, str: Union[str, dict]])
FunctionReturn = NewType('FunctionReturn', dict[str: bool, str: any]) #MagicTokenPayload , dict insted of any