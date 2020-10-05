Attribute VB_Name = "Module1"
Sub LoopThroughSlides()

Dim sld As Slide
Dim list As String
'Loop Through Each Slide in ActivePresentation
  For Each sld In ActivePresentation.Slides
    
    'Do something...(ie add a transition to slides)
    If sld.CustomLayout.Name = "VulnDetail" Then
        list = list & sld.Shapes.Placeholders.Item(2).TextFrame.TextRange.Text & "|" & sld.Shapes.Placeholders.Item(3).TextFrame.TextRange.Text & "|" & sld.Shapes.Placeholders.Item(7).TextFrame.TextRange.Text & "|" & sld.Shapes.Placeholders.Item(6).TextFrame.TextRange.Text & "|" & sld.Shapes.Placeholders.Item(8).TextFrame.TextRange.Text & vbCrLf
    End If

  Next sld
  Dim newSlide As Slide
  Set newSlide = ActivePresentation.Slides(1)
  newSlide.Shapes.AddTextbox(Orientation:=msoTextOrientationHorizontal, _
    Left:=100, Top:=100, Width:=200, Height:=50).TextFrame _
    .TextRange.Text = list
    

                
End Sub
